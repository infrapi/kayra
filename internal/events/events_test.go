package events

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

const compute = "system:api:compute.infrapi.io"

type rig struct {
	t      *testing.T
	engine *gin.Engine
	store  *store.LocalStore
	out    *bytes.Buffer
	now    time.Time
}

// newRig serves events on a LocalStore. The caller is the X-User header;
// jdoe reads core, ops writes it, core is subscribed to compute.infrapi.io,
// other is not, nope does not exist.
func newRig(t *testing.T, settings config.EventsSettings) *rig {
	gin.SetMode(gin.TestMode)
	s, err := store.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, engine: gin.New(), store: s, out: &bytes.Buffer{}, now: time.Now()}
	gate := func(c *gin.Context) {
		if u := c.GetHeader("X-User"); u != "" {
			middleware.SetAuth(c, &middleware.AuthContext{UserID: u})
		}
		c.Next()
	}
	Register(r.engine, gate, Options{
		Store: s, Keys: store.Keys{Prefix: "/t"}, Settings: settings, Stdout: r.out,
		Now: func() time.Time { return r.now },
		Namespace: func(ns string) *liberrors.Error {
			if ns == "nope" {
				return liberrors.New(http.StatusNotFound, "t", "namespace %q not found", ns)
			}
			return nil
		},
		Authorize: func(ac *middleware.AuthContext, ns, verb string) (bool, string, error) {
			switch {
			case ac.UserID == "jdoe" && ns == "core" && (verb == "get" || verb == "list"):
				return true, "", nil
			case ac.UserID == "ops" && ns == "core":
				return true, "", nil
			}
			return false, "no role grants it", nil
		},
		Subscribed: func(ns, api string) *liberrors.Error {
			if ns == "core" && api == "compute.infrapi.io" {
				return nil
			}
			return liberrors.New(http.StatusForbidden, "t", "namespace %q is not subscribed to %q", ns, api)
		},
	})
	return r
}

func (r *rig) call(user, method, path, body string) (int, []byte, http.Header) {
	r.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if user != "" {
		req.Header.Set("X-User", user)
	}
	w := httptest.NewRecorder()
	r.engine.ServeHTTP(w, req)
	return w.Code, w.Body.Bytes(), w.Header()
}

const base = "/apis/events.infrapi.io/v1/namespaces/core/events"

func event(name, reason, typ string) string {
	return fmt.Sprintf(`{"regarding":{"api":"compute.infrapi.io","resource":"vms","name":%q},"type":%q,"reason":%q,"reporting_controller":"compute","note":"n","action":"create","user":"jdoe","request_id":"r1"}`, name, typ, reason)
}

func settings() config.EventsSettings {
	return config.EventsSettings{TTL: time.Hour, Stdout: true, PerSecond: 50, Burst: 200}
}

// An API reports about its own objects, in a namespace subscribed to it;
// Kayra sets id, received_at and reporter; one, or a batch.
func TestCreate(t *testing.T) {
	r := newRig(t, settings())
	code, body, _ := r.call(compute, http.MethodPost, base, event("web-1", "VMCreated", "Normal"))
	var e Event
	if code != http.StatusCreated || json.Unmarshal(body, &e) != nil || e.ID == "" || e.Reporter != compute || e.ReceivedAt.IsZero() ||
		e.Regarding.Namespace != "core" || e.Time.IsZero() {
		t.Fatalf("%d %s", code, body)
	}
	if !strings.Contains(r.out.String(), `"reason":"VMCreated"`) {
		t.Errorf("stdout: %q", r.out.String())
	}
	batch := `{"items":[` + event("web-2", "VMCreated", "Normal") + `,` + event("web-3", "VMCreateFailed", "Warning") + `]}`
	if code, body, _ := r.call(compute, http.MethodPost, base, batch); code != http.StatusCreated || !strings.Contains(string(body), `"items"`) {
		t.Fatalf("batch: %d %s", code, body)
	}
	// set by Kayra, never by the caller
	forged := strings.Replace(event("web-4", "VMCreated", "Normal"), `{"regarding"`, `{"reporter":"system:api:other.infrapi.io","id":"x","regarding"`, 1)
	_, body, _ = r.call(compute, http.MethodPost, base, forged)
	if json.Unmarshal(body, &e) != nil || e.Reporter != compute || e.ID == "x" {
		t.Errorf("forged: %s", body)
	}

	for what, c := range map[string]struct {
		user, path, body string
		code             int
	}{
		"another API's object":   {compute, base, strings.Replace(event("x", "VMCreated", "Normal"), `"api":"compute.infrapi.io"`, `"api":"network.infrapi.io"`, 1), http.StatusForbidden},
		"not subscribed":         {compute, strings.Replace(base, "core", "other", 1), event("x", "VMCreated", "Normal"), http.StatusForbidden},
		"no namespace":           {compute, strings.Replace(base, "core", "nope", 1), event("x", "VMCreated", "Normal"), http.StatusNotFound},
		"a reader":               {"jdoe", base, event("x", "VMCreated", "Normal"), http.StatusForbidden},
		"anonymous":              {"", base, event("x", "VMCreated", "Normal"), http.StatusUnauthorized},
		"no PascalCase":          {compute, base, event("x", "vm created", "Normal"), http.StatusBadRequest},
		"a type":                 {compute, base, event("x", "VMCreated", "Info"), http.StatusBadRequest},
		"another namespace":      {compute, base, strings.Replace(event("x", "VMCreated", "Normal"), `"resource"`, `"namespace":"other","resource"`, 1), http.StatusBadRequest},
		"an unknown field":       {compute, base, strings.Replace(event("x", "VMCreated", "Normal"), `"note"`, `"color":"red","note"`, 1), http.StatusBadRequest},
		"no controller":          {compute, base, strings.Replace(event("x", "VMCreated", "Normal"), `"reporting_controller":"compute",`, ``, 1), http.StatusBadRequest},
		"an empty batch":         {compute, base, `{"items":[]}`, http.StatusBadRequest},
		"with the RBAC (a user)": {"ops", base, event("x", "VMCreated", "Normal"), http.StatusCreated},
	} {
		if code, body, _ := r.call(c.user, http.MethodPost, c.path, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", what, code, body, c.code)
		}
	}
	// cluster-scoped: an API's own, whatever the namespaces
	if code, body, _ := r.call(compute, http.MethodPost, "/apis/events.infrapi.io/v1/events", event("h-1", "HostDrained", "Normal")); code != http.StatusCreated {
		t.Errorf("cluster: %d %s", code, body)
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if code, _, _ := r.call(compute, m, base+"/"+e.ID, "{}"); code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, code)
		}
	}
}

// The list: newest first, filtered, its readers only; get one.
func TestList(t *testing.T) {
	r := newRig(t, settings())
	for i := range 5 {
		typ, reason := "Normal", "VMCreated"
		if i%2 == 1 {
			typ, reason = "Warning", "VMCreateFailed"
		}
		r.call(compute, http.MethodPost, base, event(fmt.Sprintf("web-%d", i), reason, typ))
		time.Sleep(2 * time.Millisecond) // a UUIDv7 per millisecond
	}
	list := func(user, query string) (int, []Event) {
		t.Helper()
		code, body, _ := r.call(user, http.MethodGet, base+query, "")
		var out []Event
		_ = json.Unmarshal(body, &out)
		return code, out
	}
	code, all := list("jdoe", "")
	if code != http.StatusOK || len(all) != 5 || all[0].Regarding.Name != "web-4" {
		t.Fatalf("%d %+v", code, all)
	}
	if _, w := list("jdoe", "?type=Warning"); len(w) != 2 || w[0].Reason != "VMCreateFailed" {
		t.Errorf("type: %+v", w)
	}
	if _, w := list("jdoe", "?regarding.name=web-2&reporter="+compute); len(w) != 1 {
		t.Errorf("regarding.name: %+v", w)
	}
	if _, w := list("jdoe", "?limit=2"); len(w) != 2 || w[1].Regarding.Name != "web-3" {
		t.Errorf("limit: %+v", w)
	}
	if _, w := list("jdoe", "?since="+all[1].ReceivedAt.Add(-time.Hour).Format(time.RFC3339)); len(w) != 5 {
		t.Errorf("since an hour: %d", len(w))
	}
	if _, w := list("jdoe", "?until=2000-01-01T00:00:00Z"); len(w) != 0 {
		t.Errorf("until 2000: %d", len(w))
	}
	if code, _ := list("jdoe", "?color=red"); code != http.StatusBadRequest {
		t.Errorf("an unknown filter: %d", code)
	}
	if code, _ := list("mallory", ""); code != http.StatusForbidden {
		t.Errorf("no reader: %d", code)
	}
	if code, body, _ := r.call("jdoe", http.MethodGet, base+"/"+all[2].ID, ""); code != http.StatusOK || !strings.Contains(string(body), all[2].ID) {
		t.Errorf("get: %d %s", code, body)
	}
	if code, _, _ := r.call("jdoe", http.MethodGet, base+"/nope", ""); code != http.StatusNotFound {
		t.Errorf("get a missing one: %d", code)
	}
}

// PATCH: the series only, by its reporter only, never fewer.
func TestPatchSeries(t *testing.T) {
	r := newRig(t, settings())
	_, body, _ := r.call(compute, http.MethodPost, base, event("web-1", "VMCreateFailed", "Warning"))
	var e Event
	_ = json.Unmarshal(body, &e)
	path := base + "/" + e.ID
	code, body, _ := r.call(compute, http.MethodPatch, path, `{"series":{"count":30}}`)
	if code != http.StatusOK || json.Unmarshal(body, &e) != nil || e.Series == nil || e.Series.Count != 30 || e.Series.LastObserved.IsZero() {
		t.Fatalf("%d %s", code, body)
	}
	for what, c := range map[string]struct {
		user, body string
		code       int
	}{
		"another reporter": {"ops", `{"series":{"count":31}}`, http.StatusForbidden},
		"fewer":            {compute, `{"series":{"count":3}}`, http.StatusBadRequest},
		"another field":    {compute, `{"series":{"count":31},"note":"x"}`, http.StatusBadRequest},
		"no series":        {compute, `{}`, http.StatusBadRequest},
	} {
		if code, body, _ := r.call(c.user, http.MethodPatch, path, c.body); code != c.code {
			t.Errorf("%s: %d %s, want %d", what, code, body, c.code)
		}
	}
}

// A reporter over its rate: a 429 with Retry-After, others unaffected.
func TestRateLimit(t *testing.T) {
	r := newRig(t, config.EventsSettings{TTL: time.Hour, PerSecond: 1, Burst: 3})
	for i := range 3 {
		if code, body, _ := r.call(compute, http.MethodPost, base, event("web", "VMCreated", "Normal")); code != http.StatusCreated {
			t.Fatalf("%d: %d %s", i, code, body)
		}
	}
	code, _, h := r.call(compute, http.MethodPost, base, event("web", "VMCreated", "Normal"))
	if code != http.StatusTooManyRequests || h.Get("Retry-After") == "" {
		t.Fatalf("over the rate: %d %v", code, h)
	}
	if code, _, _ := r.call("ops", http.MethodPost, base, event("web", "VMCreated", "Normal")); code != http.StatusCreated {
		t.Errorf("another reporter: %d", code)
	}
	r.now = r.now.Add(2 * time.Second)
	if code, _, _ := r.call(compute, http.MethodPost, base, event("web", "VMCreated", "Normal")); code != http.StatusCreated {
		t.Errorf("after the wait: %d", code)
	}
}

// Events expire after their ttl.
func TestExpiry(t *testing.T) {
	r := newRig(t, config.EventsSettings{TTL: 50 * time.Millisecond, PerSecond: 50, Burst: 200})
	r.call(compute, http.MethodPost, base, event("web", "VMCreated", "Normal"))
	time.Sleep(100 * time.Millisecond)
	_, body, _ := r.call("jdoe", http.MethodGet, base, "")
	if strings.TrimSpace(string(body)) != "[]" {
		t.Errorf("expired: %s", body)
	}
}

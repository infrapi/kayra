package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Options configure the routes.
type Options struct {
	Store    store.Store
	Keys     store.Keys
	Settings config.EventsSettings
	// Namespace is a namespace that exists: nil, or a 404.
	Namespace func(namespace string) *liberrors.Error
	// Authorize decides verb on events in namespace ("" the cluster's) by
	// the RBAC: the namespace's roles, or the cluster's.
	Authorize func(ac *middleware.AuthContext, namespace, verb string) (allowed bool, reason string, err error)
	// Subscribed is namespace subscribed to api, its subscription active:
	// nil, or why not. An API reports in such a namespace only.
	Subscribed func(namespace, api string) *liberrors.Error
	// Stdout receives each accepted event, a JSON line, with Settings.Stdout.
	Stdout io.Writer
	// Now is the clock, time.Now when nil.
	Now func() time.Time
}

var receivedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "kayra_events_received_total", Help: "Events received, by result: accepted, invalid, denied, limited.",
}, []string{"result"})

func init() { prometheus.MustRegister(receivedTotal) }

type server struct {
	o     Options
	limit *limiter
	outMu sync.Mutex
}

// Register mounts events.<domain> on r, behind gate (the authenticator):
//
//	POST  /apis/events.<domain>/v1/namespaces/:namespace/events      an event, or {"items": [...]}
//	GET   /apis/events.<domain>/v1/namespaces/:namespace/events      filtered, newest first
//	GET   /apis/events.<domain>/v1/namespaces/:namespace/events/:id
//	PATCH /apis/events.<domain>/v1/namespaces/:namespace/events/:id  its series, by its reporter
//
// and the same without namespaces/:namespace, the cluster's. PUT and
// DELETE are 405: an event is never changed but for its series.
func Register(r gin.IRouter, gate gin.HandlerFunc, o Options) {
	if o.Now == nil {
		o.Now = time.Now
	}
	s := &server{o: o, limit: newLimiter(o.Settings.PerSecond, o.Settings.Burst, o.Now)}
	root := r.Group("/apis/"+API+"/v1", gate)
	for _, base := range []string{"/namespaces/:namespace/events", "/events"} {
		root.POST(base, s.create)
		root.GET(base, s.list)
		root.GET(base+"/:id", s.get)
		root.PATCH(base+"/:id", s.patch)
		for _, m := range []string{http.MethodPut, http.MethodDelete} {
			root.Handle(m, base+"/:id", notAllowed)
			root.Handle(m, base, notAllowed)
		}
	}
}

func notAllowed(c *gin.Context) {
	c.Header("Allow", "GET, POST, PATCH")
	httpapi.Fail(c, liberrors.New(http.StatusMethodNotAllowed, "events", "an event is never replaced nor deleted: it expires; PATCH changes its series only"))
}

// caller is the request's caller and namespace, the namespace checked.
func (s *server) caller(c *gin.Context) (*middleware.AuthContext, string, bool) {
	ac, ok := middleware.GetAuth(c)
	if !ok {
		httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "events", "not authenticated"))
		return nil, "", false
	}
	ns := c.Param("namespace")
	if ns != "" && s.o.Namespace != nil {
		if err := s.o.Namespace(ns); err != nil {
			httpapi.Fail(c, err)
			return nil, "", false
		}
	}
	return ac, ns, true
}

// authorize decides verb by the RBAC, a 403 with its reason when denied.
func (s *server) authorize(c *gin.Context, ac *middleware.AuthContext, ns, verb string) bool {
	allowed, reason, err := s.o.Authorize(ac, ns, verb)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "events", ""))
		return false
	}
	if !allowed {
		httpapi.Fail(c, liberrors.New(http.StatusForbidden, "events", "not authorized to %s events: %s", verb, reason))
		return false
	}
	return true
}

func (s *server) create(c *gin.Context) {
	ac, ns, ok := s.caller(c)
	if !ok {
		return
	}
	evs, batch, err := decodeEvents(c.Request.Body)
	if err != nil {
		receivedTotal.WithLabelValues("invalid").Inc()
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "%s", err))
		return
	}
	for i := range evs {
		if err := evs[i].validate(ns); err != nil {
			receivedTotal.WithLabelValues("invalid").Add(float64(len(evs)))
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "items[%d]: %s", i, err))
			return
		}
	}
	if !s.mayReport(c, ac, ns, evs) {
		receivedTotal.WithLabelValues("denied").Add(float64(len(evs)))
		return
	}
	if ok, wait := s.limit.take(ac.UserID, len(evs)); !ok {
		receivedTotal.WithLabelValues("limited").Add(float64(len(evs)))
		c.Header("Retry-After", strconv.Itoa(int(wait.Round(time.Second)/time.Second)))
		httpapi.Fail(c, liberrors.New(http.StatusTooManyRequests, "events", "%s reports too many events: %g a second, %d at once", ac.UserID, s.o.Settings.PerSecond, s.o.Settings.Burst))
		return
	}

	now := s.o.Now().UTC()
	kvs := make([]store.KV, 0, len(evs))
	for i := range evs {
		e := &evs[i]
		id, err := uuid.NewV7()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "events", ""))
			return
		}
		e.ID, e.ReceivedAt, e.Reporter = id.String(), now, ac.UserID
		if e.Time.IsZero() {
			e.Time = now
		}
		data, _ := json.Marshal(e)
		kvs = append(kvs, store.KV{Key: s.o.Keys.Event(ns, e.ID), Value: data})
	}
	if err := s.o.Store.PutBatchTTL(kvs, s.o.Settings.TTL); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", ""))
		return
	}
	receivedTotal.WithLabelValues("accepted").Add(float64(len(evs)))
	s.print(kvs)
	if batch {
		c.JSON(http.StatusCreated, gin.H{"items": evs})
		return
	}
	c.JSON(http.StatusCreated, evs[0])
}

// mayReport decides who reports: an API about its own objects, in a
// namespace subscribed to it (the cluster's events too); anyone else as the
// RBAC grants create on events.
func (s *server) mayReport(c *gin.Context, ac *middleware.AuthContext, ns string, evs []Event) bool {
	group, isAPI := identity.ParseAPI(ac.UserID)
	if !isAPI {
		return s.authorize(c, ac, ns, "create")
	}
	for i, e := range evs {
		if e.Regarding.API != group {
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, "events", "items[%d]: %s reports about its own objects only, not %q's", i, ac.UserID, e.Regarding.API))
			return false
		}
	}
	if ns != "" && s.o.Subscribed != nil {
		if err := s.o.Subscribed(ns, group); err != nil {
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, "events", "%s reports in the namespaces subscribed to it only: %s", ac.UserID, err.Message))
			return false
		}
	}
	return true
}

// decodeEvents reads one event, or {"items": [...]}: at most MaxBatch.
func decodeEvents(body io.Reader) ([]Event, bool, error) {
	data, err := io.ReadAll(io.LimitReader(body, 1<<20))
	if err != nil {
		return nil, false, err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, false, fmt.Errorf("an event, or {\"items\": [...]}: %w", err)
	}
	strict := func(raw []byte, into any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		return d.Decode(into)
	}
	if items, ok := probe["items"]; ok && len(probe) == 1 {
		var evs []Event
		if err := strict(items, &evs); err != nil {
			return nil, true, err
		}
		if len(evs) == 0 || len(evs) > MaxBatch {
			return nil, true, fmt.Errorf("items: 1 to %d events", MaxBatch)
		}
		return evs, true, nil
	}
	var e Event
	if err := strict(data, &e); err != nil {
		return nil, false, err
	}
	return []Event{e}, false, nil
}

func (s *server) print(kvs []store.KV) {
	if !s.o.Settings.Stdout || s.o.Stdout == nil {
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	for _, kv := range kvs {
		_, _ = s.o.Stdout.Write(append(kv.Value, '\n'))
	}
}

func (s *server) get(c *gin.Context) {
	ac, ns, ok := s.caller(c)
	if !ok || !s.authorize(c, ac, ns, "get") {
		return
	}
	e, err := s.read(ns, c.Param("id"))
	if err != nil {
		httpapi.Fail(c, err)
		return
	}
	c.JSON(http.StatusOK, e)
}

func (s *server) read(ns, id string) (Event, *liberrors.Error) {
	var e Event
	data, err := s.o.Store.Get(s.o.Keys.Event(ns, id))
	if errors.Is(err, store.ErrNotFound) {
		return e, liberrors.New(http.StatusNotFound, "events", "event %q not found: it may have expired", id)
	}
	if err == nil {
		err = json.Unmarshal(data, &e)
	}
	if err != nil {
		return e, liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
	}
	return e, nil
}

// patch changes an event's series, by its reporter only: the key written
// again, so its ttl counts from now.
func (s *server) patch(c *gin.Context) {
	ac, ns, ok := s.caller(c)
	if !ok {
		return
	}
	e, ferr := s.read(ns, c.Param("id"))
	if ferr != nil {
		httpapi.Fail(c, ferr)
		return
	}
	if e.Reporter != ac.UserID {
		httpapi.Fail(c, liberrors.New(http.StatusForbidden, "events", "only its reporter, %s, changes event %q", e.Reporter, e.ID))
		return
	}
	var body struct {
		Series *Series `json:"series"`
	}
	d := json.NewDecoder(io.LimitReader(c.Request.Body, 1<<16))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil || body.Series == nil {
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", `{"series": {"count": <n>, "last_observed": "<time>"}}, nothing else`))
		return
	}
	if body.Series.Count < 1 || (e.Series != nil && body.Series.Count < e.Series.Count) {
		httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "series.count: 1 or more, never less than it was"))
		return
	}
	if ok, wait := s.limit.take(ac.UserID, 1); !ok {
		c.Header("Retry-After", strconv.Itoa(int(wait.Round(time.Second)/time.Second)))
		httpapi.Fail(c, liberrors.New(http.StatusTooManyRequests, "events", "%s reports too many events", ac.UserID))
		return
	}
	if body.Series.LastObserved.IsZero() {
		body.Series.LastObserved = s.o.Now().UTC()
	}
	e.Series = body.Series
	data, _ := json.Marshal(e)
	if err := s.o.Store.PutBatchTTL([]store.KV{{Key: s.o.Keys.Event(ns, e.ID), Value: data}}, s.o.Settings.TTL); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", ""))
		return
	}
	c.JSON(http.StatusOK, e)
}

// filters are list's query parameters, matched exactly.
var filters = []string{"type", "reason", "action", "user", "reporter", "reporting_controller", "regarding.api", "regarding.resource", "regarding.name"}

func (e Event) field(name string) string {
	switch name {
	case "type":
		return e.Type
	case "reason":
		return e.Reason
	case "action":
		return e.Action
	case "user":
		return e.User
	case "reporter":
		return e.Reporter
	case "reporting_controller":
		return e.ReportingController
	case "regarding.api":
		return e.Regarding.API
	case "regarding.resource":
		return e.Regarding.Resource
	case "regarding.name":
		return e.Regarding.Name
	}
	return ""
}

const (
	pageSize   = 500
	maxScanned = 20000
	maxLimit   = 1000
)

// list is the namespace's events, newest received first: since and until
// (RFC 3339, or a duration back from now: 1h) bound the reception, limit
// (100, at most 1000) their number, the other parameters match exactly.
func (s *server) list(c *gin.Context) {
	ac, ns, ok := s.caller(c)
	if !ok || !s.authorize(c, ac, ns, "list") {
		return
	}
	q := c.Request.URL.Query()
	for k := range q {
		if !contains(filters, k) && k != "since" && k != "until" && k != "limit" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "unknown filter %q: %s, since, until or limit", k, strings.Join(filters, ", ")))
			return
		}
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxLimit {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "limit: 1 to %d", maxLimit))
			return
		}
		limit = n
	}
	prefix := s.o.Keys.EventsPrefix(ns)
	from, to := prefix, prefix+"~"
	for _, b := range []struct {
		name  string
		into  *string
		upper bool
	}{{"since", &from, false}, {"until", &to, true}} {
		v := q.Get(b.name)
		if v == "" {
			continue
		}
		t, err := s.when(v)
		if err != nil {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "events", "%s %q: a time (RFC 3339) or a duration back from now (1h)", b.name, v))
			return
		}
		*b.into = prefix + idAt(t)
	}

	out := []Event{}
	scanned := 0
	for len(out) < limit && scanned < maxScanned {
		page, err := s.o.Store.Range(from, to, pageSize, true)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", ""))
			return
		}
		for _, kv := range page {
			var e Event
			if json.Unmarshal(kv.Value, &e) != nil {
				log.Printf("events: undecodable %s", kv.Key)
				continue
			}
			if matches(e, q) {
				out = append(out, e)
				if len(out) == limit {
					break
				}
			}
		}
		scanned += len(page)
		if len(page) < pageSize {
			break
		}
		to = page[len(page)-1].Key
	}
	c.JSON(http.StatusOK, out)
}

func (s *server) when(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return time.Time{}, err
	}
	return s.o.Now().Add(-d), nil
}

// idAt is the smallest UUIDv7 of t's millisecond: a key bound.
func idAt(t time.Time) string {
	ms := uint64(max(t.UnixMilli(), 0))
	return fmt.Sprintf("%08x-%04x-0000-0000-000000000000", ms>>16, ms&0xffff)
}

func matches(e Event, q map[string][]string) bool {
	for _, f := range filters {
		if v, ok := q[f]; ok && len(v) > 0 && e.field(f) != v[0] {
			return false
		}
	}
	return true
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

package apiserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/audit"
	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
)

type memorySink struct {
	mu   sync.Mutex
	recs []audit.Record
}

func (m *memorySink) Write(r audit.Record) { m.mu.Lock(); m.recs = append(m.recs, r); m.mu.Unlock() }

func (m *memorySink) Close(context.Context) error { return nil }

func (m *memorySink) take() []audit.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.recs
	m.recs = nil
	return out
}

// The audit, on a real engine: a write to Kayra's own routes (stage
// request, its status and name), a denial, an unauthenticated call, an
// allowed read left out unless reads; /check's decisions (stage check),
// with the original request's context; never the -/ routes.
func TestAudit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := testKayraConfig(t)
	sink := &memorySink{}
	engine, err := Build(testAppConfig(), cfg, WithAudit(audit.NewAuditor(sink, false)))
	if err != nil {
		t.Fatal(err)
	}
	root := mintSysadminToken(t, cfg)
	call := func(token, method, path, body string, headers ...string) int {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "infrapi-cli/test")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		for i := 0; i+1 < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		req.RemoteAddr = "203.0.113.12:4242"
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		return w.Code
	}

	if code := call(root, http.MethodPost, "/apis/system.infrapi.io/v1/namespaces", `{"name":"core"}`, "X-Request-Id", "req-1"); code != http.StatusCreated {
		t.Fatalf("create namespace: %d", code)
	}
	recs := sink.take()
	if len(recs) != 1 {
		t.Fatalf("%+v", recs)
	}
	r := recs[0]
	if r.Stage != audit.StageRequest || r.RequestID != "req-1" || r.User != "bootstrap" || r.API != "system.infrapi.io" ||
		r.Resource != "namespaces" || r.Verb != "create" || !r.Allowed || r.Status != http.StatusCreated ||
		r.SourceIP != "203.0.113.12" || r.UserAgent != "infrapi-cli/test" {
		t.Errorf("create: %+v", r)
	}

	// an allowed read: not audited; -/ routes: never
	call(root, http.MethodGet, "/apis/system.infrapi.io/v1/namespaces/core", "")
	call("", http.MethodGet, "/apis/system.infrapi.io/v1/-/healthz", "")
	if recs := sink.take(); len(recs) != 0 {
		t.Errorf("reads audited: %+v", recs)
	}

	// no token, and a delete refused to a non-admin: denials, read or not
	call("", http.MethodGet, "/apis/catalog.infrapi.io/v1/apiregistrations", "")
	nobody := mintToken(t, cfg, "nobody")
	call(nobody, http.MethodDelete, "/apis/system.infrapi.io/v1/namespaces/core", "")
	recs = sink.take()
	if len(recs) != 2 || recs[0].Status != http.StatusUnauthorized || recs[0].Allowed || recs[0].Verb != "list" ||
		recs[1].Status != http.StatusForbidden || recs[1].User != "nobody" || recs[1].Name != "core" || recs[1].Verb != "delete" || recs[1].Reason == "" {
		t.Errorf("denials: %+v", recs)
	}

	// /check: one record per decision, the app's request as it received it
	call(nobody, http.MethodPost, "/apis/authorization.infrapi.io/v1/check",
		`{"namespace":"core","api":"compute.infrapi.io","resource":"vms","verb":"create","request_id":"req-2","source_ip":"198.51.100.7","user_agent":"curl/8"}`)
	call(nobody, http.MethodPost, "/apis/authorization.infrapi.io/v1/check", `{"namespace":"nope","api":"compute.infrapi.io","resource":"vms","verb":"get"}`)
	recs = sink.take()
	if len(recs) != 2 {
		t.Fatalf("check: %+v", recs)
	}
	c := recs[0]
	if c.Stage != audit.StageCheck || c.RequestID != "req-2" || c.SourceIP != "198.51.100.7" || c.UserAgent != "curl/8" ||
		c.User != "nobody" || c.Namespace != "core" || c.API != "compute.infrapi.io" || c.Allowed || c.Reason == "" || c.Status != 0 {
		t.Errorf("check denied: %+v", c)
	}
	if recs[1].Status != http.StatusNotFound || recs[1].Allowed || recs[1].SourceIP != "203.0.113.12" {
		t.Errorf("check on a missing namespace: %+v", recs[1])
	}

	// reads: true
	sink2 := &memorySink{}
	engine2, _ := Build(testAppConfig(), cfg, WithAudit(audit.NewAuditor(sink2, true)))
	req := httptest.NewRequest(http.MethodGet, "/apis/system.infrapi.io/v1/namespaces/core", nil)
	req.Header.Set("Authorization", "Bearer "+root)
	engine2.ServeHTTP(httptest.NewRecorder(), req)
	if recs := sink2.take(); len(recs) != 1 || recs[0].Verb != "get" || recs[0].Name != "core" {
		t.Errorf("reads: true: %+v", recs)
	}
}

// mintToken signs a self-JWT of sub, no group of its own.
func mintToken(t *testing.T, cfg *gconfig.Config, sub string) string {
	t.Helper()
	keys, err := gcrypto.LoadSigningKeys(cfg.Authentifications["self"].Local)
	if err != nil {
		t.Fatal(err)
	}
	token, err := gcrypto.MintSelfJWT(keys[0], sub, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

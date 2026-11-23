package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/infrapi/kayra/internal/config"
)

// memory keeps what it is written.
type memory struct {
	mu   sync.Mutex
	recs []Record
}

func (m *memory) Write(r Record) { m.mu.Lock(); m.recs = append(m.recs, r); m.mu.Unlock() }

func (m *memory) Close(context.Context) error { return nil }

// Writes and denials, reads only when asked.
func TestAuditor(t *testing.T) {
	m := &memory{}
	a := NewAuditor(m, false)
	a.Record(Record{Verb: "get", Allowed: true})
	a.Record(Record{Verb: "list", Allowed: true})
	a.Record(Record{Verb: "get", Allowed: false})
	a.Record(Record{Verb: "create", Allowed: true})
	if len(m.recs) != 2 || m.recs[0].Verb != "get" || m.recs[1].Verb != "create" {
		t.Fatalf("%+v", m.recs)
	}
	NewAuditor(m, true).Record(Record{Verb: "list", Allowed: true})
	if len(m.recs) != 3 {
		t.Fatal("reads: true dropped a read")
	}
	var none *Auditor
	none.Record(Record{Verb: "create"}) // a nil auditor writes nothing
}

// File: one JSON line per record, its id and time set; Reopen after the
// file was moved writes to a new one.
func TestFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	f, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(Record{Stage: StageCheck, User: "jdoe", Verb: "create"})
	lines := readLines(t, path)
	var r Record
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0]), &r) != nil || r.ID == "" || r.Time.IsZero() || r.User != "jdoe" {
		t.Fatalf("%v", lines)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// logrotate moves it, SIGHUP
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write(Record{User: "asmith"})
	if got := readLines(t, path); len(got) != 1 || !strings.Contains(got[0], "asmith") {
		t.Fatalf("after reopen: %v", got)
	}
	if got := readLines(t, path+".1"); len(got) != 1 {
		t.Fatalf("the rotated file: %v", got)
	}
	_ = f.Close(context.Background())
	if _, err := NewFile(filepath.Join(dir, "missing", "audit.log")); err == nil {
		t.Error("a file in no directory")
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		out = append(out, s.Text())
	}
	return out
}

// API: batches of max_events, or after max_wait; the headers, ${VAR}
// expanded; retried on a 503; Close sends what is queued.
func TestAPI(t *testing.T) {
	retryWait = 10 * time.Millisecond
	t.Setenv("SIEM_TOKEN", "s3cret")
	var mu sync.Mutex
	var batches [][]Record
	var fails atomic.Int32
	fails.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" || r.Header.Get("X-Source") != "kayra" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if fails.Add(-1) >= 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var body struct{ Items []Record }
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		batches = append(batches, body.Items)
		mu.Unlock()
	}))
	defer srv.Close()
	cfg := config.AuditAPIConfig{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer ${SIEM_TOKEN}", "X-Source": "kayra"},
		Batch: config.AuditBatchConfig{MaxEvents: 3, MaxWait: "50ms"}}
	a, err := NewAPI(cfg)
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(sendErrorsTotal)
	for i := range 4 {
		a.Write(Record{User: "u", Verb: "create", Resource: string(rune('a' + i))})
	}
	time.Sleep(300 * time.Millisecond) // 3 at once, the 4th after max_wait
	a.Write(Record{User: "last"})
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	n := 0
	for _, b := range batches {
		n += len(b)
		if len(b) > 3 {
			t.Errorf("a batch of %d", len(b))
		}
	}
	if n != 5 || len(batches[0]) != 3 || batches[0][0].ID == "" {
		t.Fatalf("batches: %+v", batches)
	}
	if testutil.ToFloat64(sendErrorsTotal) != before+1 {
		t.Errorf("the 503 was not counted")
	}

	t.Setenv("SIEM_TOKEN", "")
	if _, err := NewAPI(config.AuditAPIConfig{URL: srv.URL, Headers: map[string]string{"Authorization": "${NOPE_UNSET}"}}); err == nil || !strings.Contains(err.Error(), "NOPE_UNSET") {
		t.Errorf("an unset variable: %v", err)
	}
}

// A refusal (4xx) is not retried: the batch is dropped and counted; a full
// queue drops the record.
func TestAPIDrops(t *testing.T) {
	retryWait = 10 * time.Millisecond
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	dropped := testutil.ToFloat64(droppedTotal.WithLabelValues("send_failed"))
	a, _ := NewAPI(config.AuditAPIConfig{URL: srv.URL, Batch: config.AuditBatchConfig{MaxEvents: 1}})
	a.Write(Record{User: "u"})
	_ = a.Close(context.Background())
	if posts.Load() != 1 || testutil.ToFloat64(droppedTotal.WithLabelValues("send_failed")) != dropped+1 {
		t.Errorf("posts %d", posts.Load())
	}

	full := testutil.ToFloat64(droppedTotal.WithLabelValues("queue_full"))
	q := &API{queue: make(chan Record, 1)}
	q.Write(Record{})
	q.Write(Record{})
	if testutil.ToFloat64(droppedTotal.WithLabelValues("queue_full")) != full+1 {
		t.Error("a full queue kept the record")
	}
}

func TestNew(t *testing.T) {
	if s, err := New(config.AuditConfig{}); err != nil || s != (None{}) {
		t.Fatalf("%v %v", s, err)
	}
	s, err := New(config.AuditConfig{Backend: "file", File: config.AuditFileConfig{Path: "-"}})
	if _, ok := s.(*File); err != nil || !ok {
		t.Fatalf("%T %v", s, err)
	}
}

// splunk-hec: one event object per record, back to back, its time the
// record's, the HEC metadata set; Splunk's own 503 retried.
func TestAPISplunkHEC(t *testing.T) {
	retryWait = 10 * time.Millisecond
	t.Setenv("SPLUNK_HEC_TOKEN", "hec-token")
	var mu sync.Mutex
	var events []map[string]any
	var busy atomic.Bool
	busy.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/event" || r.Header.Get("Authorization") != "Splunk hec-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"text":"Token is required","code":2}`))
			return
		}
		if busy.CompareAndSwap(true, false) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"text":"Server is busy","code":9}`))
			return
		}
		d := json.NewDecoder(r.Body)
		for {
			var ev map[string]any
			if err := d.Decode(&ev); err != nil {
				break
			}
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		}
		_, _ = w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()
	a, err := NewAPI(config.AuditAPIConfig{URL: srv.URL + "/services/collector/event", Format: config.AuditFormatSplunkHEC,
		Headers:   map[string]string{"Authorization": "Splunk ${SPLUNK_HEC_TOKEN}"},
		SplunkHEC: config.SplunkHECConfig{Index: "kayra", Sourcetype: "kayra:audit"},
		Batch:     config.AuditBatchConfig{MaxEvents: 10, MaxWait: "20ms"}})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 23, 18, 42, 7, 311_000_000, time.UTC)
	a.Write(Record{Time: when, User: "jdoe", Verb: "delete", Allowed: false})
	a.Write(Record{User: "asmith", Verb: "create", Allowed: true})
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 {
		t.Fatalf("events: %v", events)
	}
	e := events[0]
	ev, _ := e["event"].(map[string]any)
	if e["time"] != 1795459327.311 || e["index"] != "kayra" || e["sourcetype"] != "kayra:audit" || e["host"] != nil ||
		ev["user"] != "jdoe" || ev["verb"] != "delete" || ev["allowed"] != false || ev["id"] == "" {
		t.Errorf("event: %v", e)
	}
}

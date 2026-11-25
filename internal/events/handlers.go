package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/infrapi/kayra/api"
	"github.com/infrapi/kayra/internal/config"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Options configure the events API.
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

// Server is events.<domain>, the generated Handlers: Register mounts it,
// behind the authenticator and httpapi.WithRequest.
//
//	POST  /apis/events.<domain>/v1/namespaces/:namespace/events      an event, or {"items": [...]}
//	GET   /apis/events.<domain>/v1/namespaces/:namespace/events      filtered, newest first
//	GET   /apis/events.<domain>/v1/namespaces/:namespace/events/:id
//	PATCH /apis/events.<domain>/v1/namespaces/:namespace/events/:id  its series, by its reporter
//
// and the same without namespaces/:namespace, the cluster's. An event is
// never replaced nor deleted: it expires.
type Server struct {
	o     Options
	limit *limiter
	outMu sync.Mutex
}

var _ Handlers = (*Server)(nil)

// NewServer serves events as o configures.
func NewServer(o Options) *Server {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Server{o: o, limit: newLimiter(o.Settings.PerSecond, o.Settings.Burst, o.Now)}
}

// CreateNamespaceEvents reports events in namespace.
func (s *Server) CreateNamespaceEvents(ctx context.Context, namespace string, body map[string]any) (map[string]any, error) {
	return s.create(ctx, namespace, body)
}

// CreateEvents reports the cluster's events.
func (s *Server) CreateEvents(ctx context.Context, body map[string]any) (map[string]any, error) {
	return s.create(ctx, "", body)
}

// ListNamespaceEvents lists namespace's events.
func (s *Server) ListNamespaceEvents(ctx context.Context, namespace, typeParam, reason, action, user, reporter, reportingController, regardingAPI, regardingResource, regardingName, since, until, limit string) ([]api.Event, error) {
	return s.list(ctx, namespace, filterValues(typeParam, reason, action, user, reporter, reportingController, regardingAPI, regardingResource, regardingName), since, until, limit)
}

// ListEvents lists the cluster's events.
func (s *Server) ListEvents(ctx context.Context, typeParam, reason, action, user, reporter, reportingController, regardingAPI, regardingResource, regardingName, since, until, limit string) ([]api.Event, error) {
	return s.list(ctx, "", filterValues(typeParam, reason, action, user, reporter, reportingController, regardingAPI, regardingResource, regardingName), since, until, limit)
}

// GetNamespaceEvent is one of namespace's events.
func (s *Server) GetNamespaceEvent(ctx context.Context, namespace, id string) (api.Event, error) {
	return s.get(ctx, namespace, id)
}

// GetEvent is one of the cluster's events.
func (s *Server) GetEvent(ctx context.Context, id string) (api.Event, error) {
	return s.get(ctx, "", id)
}

// PatchNamespaceEvent changes the series of one of namespace's events.
func (s *Server) PatchNamespaceEvent(ctx context.Context, namespace, id string, body api.EventPatch) (api.Event, error) {
	return s.patch(ctx, namespace, id, body)
}

// PatchEvent changes the series of one of the cluster's events.
func (s *Server) PatchEvent(ctx context.Context, id string, body api.EventPatch) (api.Event, error) {
	return s.patch(ctx, "", id, body)
}

// caller is the request's caller, the namespace checked.
func (s *Server) caller(ctx context.Context, ns string) (*middleware.AuthContext, error) {
	ac, ok := middleware.AuthOf(ctx)
	if !ok {
		return nil, liberrors.New(http.StatusUnauthorized, "events", "not authenticated")
	}
	if ns != "" && s.o.Namespace != nil {
		if err := s.o.Namespace(ns); err != nil {
			return nil, err
		}
	}
	return ac, nil
}

// authorize decides verb by the RBAC, a 403 with its reason when denied.
func (s *Server) authorize(ac *middleware.AuthContext, ns, verb string) error {
	allowed, reason, err := s.o.Authorize(ac, ns, verb)
	if err != nil {
		return liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
	}
	if !allowed {
		return liberrors.New(http.StatusForbidden, "events", "not authorized to %s events: %s", verb, reason)
	}
	return nil
}

// retryAfter sets the response's Retry-After to wait, in seconds.
func retryAfter(ctx context.Context, wait time.Duration) {
	httpapi.RequestOf(ctx).Header.Set("Retry-After", strconv.Itoa(int(wait.Round(time.Second)/time.Second)))
}

// create stores the body's events, one or a batch, and answers them in
// the same shape.
func (s *Server) create(ctx context.Context, ns string, body map[string]any) (map[string]any, error) {
	ac, err := s.caller(ctx, ns)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, liberrors.New(http.StatusBadRequest, "events", "%s", err)
	}
	evs, batch, err := decodeEvents(bytes.NewReader(raw))
	if err != nil {
		receivedTotal.WithLabelValues("invalid").Inc()
		return nil, liberrors.New(http.StatusBadRequest, "events", "%s", err)
	}
	for i := range evs {
		if err := evs[i].validate(ns); err != nil {
			receivedTotal.WithLabelValues("invalid").Add(float64(len(evs)))
			return nil, liberrors.New(http.StatusBadRequest, "events", "items[%d]: %s", i, err)
		}
	}
	if err := s.mayReport(ac, ns, evs); err != nil {
		receivedTotal.WithLabelValues("denied").Add(float64(len(evs)))
		return nil, err
	}
	if ok, wait := s.limit.take(ac.UserID, len(evs)); !ok {
		receivedTotal.WithLabelValues("limited").Add(float64(len(evs)))
		retryAfter(ctx, wait)
		return nil, liberrors.New(http.StatusTooManyRequests, "events", "%s reports too many events: %g a second, %d at once", ac.UserID, s.o.Settings.PerSecond, s.o.Settings.Burst)
	}

	now := s.o.Now().UTC()
	kvs := make([]store.KV, 0, len(evs))
	for i := range evs {
		e := &evs[i]
		id, err := uuid.NewV7()
		if err != nil {
			return nil, liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
		}
		e.ID, e.ReceivedAt, e.Reporter = id.String(), now, ac.UserID
		if e.Time.IsZero() {
			e.Time = now
		}
		data, _ := json.Marshal(e)
		kvs = append(kvs, store.KV{Key: s.o.Keys.Event(ns, e.ID), Value: data})
	}
	if err := s.o.Store.PutBatchTTL(kvs, s.o.Settings.TTL); err != nil {
		return nil, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", "")
	}
	receivedTotal.WithLabelValues("accepted").Add(float64(len(evs)))
	s.print(kvs)
	var out any = evs[0]
	if batch {
		out = map[string]any{"items": evs}
	}
	res, err := httpapi.Convert[map[string]any](out)
	if err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
	}
	return res, nil
}

// mayReport decides who reports: an API about its own objects, in a
// namespace subscribed to it (the cluster's events too); anyone else as the
// RBAC grants create on events.
func (s *Server) mayReport(ac *middleware.AuthContext, ns string, evs []Event) error {
	group, isAPI := identity.ParseAPI(ac.UserID)
	if !isAPI {
		return s.authorize(ac, ns, "create")
	}
	for i, e := range evs {
		if e.Regarding.API != group {
			return liberrors.New(http.StatusForbidden, "events", "items[%d]: %s reports about its own objects only, not %q's", i, ac.UserID, e.Regarding.API)
		}
	}
	if ns != "" && s.o.Subscribed != nil {
		if err := s.o.Subscribed(ns, group); err != nil {
			return liberrors.New(http.StatusForbidden, "events", "%s reports in the namespaces subscribed to it only: %s", ac.UserID, err.Message)
		}
	}
	return nil
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

func (s *Server) print(kvs []store.KV) {
	if !s.o.Settings.Stdout || s.o.Stdout == nil {
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	for _, kv := range kvs {
		_, _ = s.o.Stdout.Write(append(kv.Value, '\n'))
	}
}

func (s *Server) get(ctx context.Context, ns, id string) (api.Event, error) {
	ac, err := s.caller(ctx, ns)
	if err != nil {
		return api.Event{}, err
	}
	if err := s.authorize(ac, ns, "get"); err != nil {
		return api.Event{}, err
	}
	e, ferr := s.read(ns, id)
	if ferr != nil {
		return api.Event{}, ferr
	}
	return wire(e)
}

// wire is e as the API answers it.
func wire[T any](e T) (api.Event, error) {
	out, err := httpapi.Convert[api.Event](e)
	if err != nil {
		return out, liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
	}
	return out, nil
}

func (s *Server) read(ns, id string) (Event, *liberrors.Error) {
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
// again, so its ttl counts from now. The contract refuses any other field
// (additionalProperties: false).
func (s *Server) patch(ctx context.Context, ns, id string, body api.EventPatch) (api.Event, error) {
	ac, err := s.caller(ctx, ns)
	if err != nil {
		return api.Event{}, err
	}
	e, ferr := s.read(ns, id)
	if ferr != nil {
		return api.Event{}, ferr
	}
	if e.Reporter != ac.UserID {
		return api.Event{}, liberrors.New(http.StatusForbidden, "events", "only its reporter, %s, changes event %q", e.Reporter, e.ID)
	}
	series := Series{Count: int(body.Series.Count), LastObserved: body.Series.LastObserved}
	if series.Count == 0 && series.LastObserved.IsZero() {
		return api.Event{}, liberrors.New(http.StatusBadRequest, "events", `{"series": {"count": <n>, "last_observed": "<time>"}}, nothing else`)
	}
	if series.Count < 1 || (e.Series != nil && series.Count < e.Series.Count) {
		return api.Event{}, liberrors.New(http.StatusBadRequest, "events", "series.count: 1 or more, never less than it was")
	}
	if ok, wait := s.limit.take(ac.UserID, 1); !ok {
		retryAfter(ctx, wait)
		return api.Event{}, liberrors.New(http.StatusTooManyRequests, "events", "%s reports too many events", ac.UserID)
	}
	if series.LastObserved.IsZero() {
		series.LastObserved = s.o.Now().UTC()
	}
	e.Series = &series
	data, _ := json.Marshal(e)
	if err := s.o.Store.PutBatchTTL([]store.KV{{Key: s.o.Keys.Event(ns, e.ID), Value: data}}, s.o.Settings.TTL); err != nil {
		return api.Event{}, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", "")
	}
	return wire(e)
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

// filterValues are list's filters by name, those given.
func filterValues(values ...string) map[string]string {
	q := map[string]string{}
	for i, f := range filters {
		if values[i] != "" {
			q[f] = values[i]
		}
	}
	return q
}

// list is the namespace's events, newest received first: since and until
// (RFC 3339, or a duration back from now: 1h) bound the reception, limit
// (100, at most 1000) their number, the filters match exactly.
func (s *Server) list(ctx context.Context, ns string, q map[string]string, since, until, limitParam string) ([]api.Event, error) {
	ac, err := s.caller(ctx, ns)
	if err != nil {
		return nil, err
	}
	if err := s.authorize(ac, ns, "list"); err != nil {
		return nil, err
	}
	limit := 100
	if limitParam != "" {
		n, err := strconv.Atoi(limitParam)
		if err != nil || n < 1 || n > maxLimit {
			return nil, liberrors.New(http.StatusBadRequest, "events", "limit: 1 to %d", maxLimit)
		}
		limit = n
	}
	prefix := s.o.Keys.EventsPrefix(ns)
	from, to := prefix, prefix+"~"
	for _, b := range []struct {
		name, value string
		into        *string
	}{{"since", since, &from}, {"until", until, &to}} {
		if b.value == "" {
			continue
		}
		t, err := s.when(b.value)
		if err != nil {
			return nil, liberrors.New(http.StatusBadRequest, "events", "%s %q: a time (RFC 3339) or a duration back from now (1h)", b.name, b.value)
		}
		*b.into = prefix + idAt(t)
	}

	out := []Event{}
	scanned := 0
	for len(out) < limit && scanned < maxScanned {
		page, err := s.o.Store.Range(from, to, pageSize, true)
		if err != nil {
			return nil, liberrors.Wrap(err, http.StatusServiceUnavailable, "events", "")
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
	res, err := httpapi.Convert[[]api.Event](out)
	if err != nil {
		return nil, liberrors.Wrap(err, http.StatusInternalServerError, "events", "")
	}
	return res, nil
}

func (s *Server) when(v string) (time.Time, error) {
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

func matches(e Event, q map[string]string) bool {
	for f, v := range q {
		if e.field(f) != v {
			return false
		}
	}
	return true
}

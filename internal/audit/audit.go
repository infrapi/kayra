// Package audit writes Kayra's audit: who asked for what, and whether it
// was allowed. One Record per /check decision (an app's request, stage
// check) and per request to Kayra's own routes (stage request), to a file
// of JSON lines, an HTTP endpoint in batches, or nowhere (config.AuditConfig).
// It is never stored in etcd, and never holds a request's body.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/infrapi/kayra/internal/config"
)

// The stages of a record.
const (
	// StageCheck is an app's request, decided by /check: the outcome is
	// Allowed and Reason, its response status unknown to Kayra.
	StageCheck = "check"
	// StageRequest is a request to Kayra's own routes, served by Kayra: it
	// has Status too.
	StageRequest = "request"
)

// Record is one audit record.
type Record struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Stage     string    `json:"stage"`
	RequestID string    `json:"request_id,omitempty"`
	User      string    `json:"user"`
	Groups    []string  `json:"groups,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
	SourceIP  string    `json:"source_ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	API       string    `json:"api"`
	Namespace string    `json:"namespace,omitempty"`
	Resource  string    `json:"resource"`
	Name      string    `json:"name,omitempty"`
	Verb      string    `json:"verb"`
	Allowed   bool      `json:"allowed"`
	Reason    string    `json:"reason,omitempty"`
	// Status is the response's HTTP status: a request's (StageRequest), or
	// /check's own when it refused the check itself (a namespace that does
	// not exist, say).
	Status int `json:"status,omitempty"`
}

// Sink writes records. Write never blocks for long, never fails the
// request: what cannot be written is counted (kayra_audit_dropped_total).
type Sink interface {
	// Write writes r, its ID and Time set when empty.
	Write(r Record)
	// Close flushes what is pending, within ctx.
	Close(ctx context.Context) error
}

// Auditor decides which records are written, and writes them to a Sink.
type Auditor struct {
	sink  Sink
	reads bool
}

// NewAuditor writes to sink: writes and denials, reads too when reads.
func NewAuditor(sink Sink, reads bool) *Auditor {
	if sink == nil {
		sink = None{}
	}
	return &Auditor{sink: sink, reads: reads}
}

// Record writes r unless it is an allowed read (get, list) and reads are
// not audited. A nil Auditor writes nothing.
func (a *Auditor) Record(r Record) {
	if a == nil {
		return
	}
	if r.Allowed && (r.Verb == "get" || r.Verb == "list") && !a.reads {
		return
	}
	a.sink.Write(r)
}

// New is the sink cfg configures, None for none.
func New(cfg config.AuditConfig) (Sink, error) {
	switch cfg.BackendName() {
	case config.AuditFile:
		return NewFile(cfg.File.Path)
	case config.AuditAPI:
		return NewAPI(cfg.API)
	}
	return None{}, nil
}

// None writes nothing.
type None struct{}

// Write does nothing.
func (None) Write(Record) {}

// Close does nothing.
func (None) Close(context.Context) error { return nil }

// fill sets r's ID (a UUIDv7, sorting by time) and Time when empty.
func fill(r *Record) {
	if r.Time.IsZero() {
		r.Time = time.Now().UTC()
	}
	if r.ID == "" {
		if id, err := uuid.NewV7(); err == nil {
			r.ID = id.String()
		}
	}
}

var (
	recordsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kayra_audit_records_total", Help: "Audit records written, by backend.",
	}, []string{"backend"})
	droppedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "kayra_audit_dropped_total", Help: "Audit records dropped, by reason: queue_full, send_failed, write_failed.",
	}, []string{"reason"})
	sendErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kayra_audit_send_errors_total", Help: "Failed POSTs of the api backend, retries included.",
	})
)

func init() {
	prometheus.MustRegister(recordsTotal, droppedTotal, sendErrorsTotal)
}

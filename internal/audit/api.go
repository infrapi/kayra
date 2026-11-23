package audit

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/infrapi/kayra/internal/config"
)

// sendAttempts is how many times a batch is POSTed before it is dropped;
// the waits between them double from retryWait.
const sendAttempts = 4

var retryWait = 500 * time.Millisecond

// API POSTs records to an HTTP endpoint in batches, {"items": [...]},
// from a queue: Write never waits on the endpoint. A record that finds the
// queue full is dropped, a batch the endpoint refuses after the retries
// too, each counted.
type API struct {
	url     string
	format  string
	hec     config.SplunkHECConfig
	headers map[string]string
	client  *http.Client
	set     config.AuditAPISettings

	queue chan Record
	done  chan struct{}
	once  sync.Once
}

// NewAPI starts the api backend cfg configures: its headers' ${VAR} read
// from the environment now (an unset one is an error), its TLS loaded.
func NewAPI(cfg config.AuditAPIConfig) (*API, error) {
	set, err := cfg.Settings()
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for k, v := range cfg.Headers {
		var missing []string
		headers[k] = os.Expand(v, func(name string) string {
			val, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return val
		})
		if len(missing) > 0 {
			return nil, fmt.Errorf("audit.api.headers.%s: $%s is not set", k, strings.Join(missing, ", $"))
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLS.CACert != "" {
		ca, err := os.ReadFile(cfg.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("audit.api.tls.cacert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("audit.api.tls.cacert %s: no certificate", cfg.TLS.CACert)
		}
		tlsConfig.RootCAs = pool
	}
	if cfg.TLS.Cert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			return nil, fmt.Errorf("audit.api.tls: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	a := &API{
		url: cfg.URL, format: cfg.FormatName(), hec: cfg.SplunkHEC, headers: headers, set: set,
		client: &http.Client{Timeout: set.Timeout, Transport: transport},
		queue:  make(chan Record, set.Queue), done: make(chan struct{}),
	}
	go a.run()
	return a, nil
}

// Write queues r, or drops it when the queue is full.
func (a *API) Write(r Record) {
	fill(&r)
	select {
	case a.queue <- r:
	default:
		droppedTotal.WithLabelValues("queue_full").Inc()
	}
}

// Close sends what is queued, within ctx.
func (a *API) Close(ctx context.Context) error {
	a.once.Do(func() { close(a.queue) })
	select {
	case <-a.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit: records left unsent: %w", ctx.Err())
	}
}

// run batches the queue: max_events records, or max_wait after a batch's
// first, then sends it.
func (a *API) run() {
	defer close(a.done)
	var batch []Record
	timer := time.NewTimer(a.set.MaxWait)
	timer.Stop()
	flush := func() {
		if len(batch) > 0 {
			a.send(batch)
			batch = nil
		}
		timer.Stop()
	}
	for {
		select {
		case r, ok := <-a.queue:
			if !ok {
				flush()
				return
			}
			if len(batch) == 0 {
				timer.Reset(a.set.MaxWait)
			}
			batch = append(batch, r)
			if len(batch) >= a.set.MaxEvents {
				flush()
			}
		case <-timer.C:
			flush()
		}
	}
}

// send POSTs batch, again on a failure or a 5xx or 429, waiting twice as
// long each time; then drops it.
func (a *API) send(batch []Record) {
	body, err := a.encode(batch)
	if err != nil {
		droppedTotal.WithLabelValues("send_failed").Add(float64(len(batch)))
		return
	}
	wait := retryWait
	for attempt := 1; ; attempt++ {
		err := a.post(body)
		if err == nil {
			recordsTotal.WithLabelValues("api").Add(float64(len(batch)))
			return
		}
		sendErrorsTotal.Inc()
		if attempt == sendAttempts || !retryable(err) {
			droppedTotal.WithLabelValues("send_failed").Add(float64(len(batch)))
			log.Printf("audit: %d records dropped: %v", len(batch), err)
			return
		}
		time.Sleep(wait)
		wait *= 2
	}
}

// statusError is the endpoint's answer, not 2xx.
type statusError int

func (s statusError) Error() string { return fmt.Sprintf("%d", int(s)) }

func retryable(err error) bool {
	if s, ok := err.(statusError); ok {
		return s >= 500 || s == http.StatusTooManyRequests
	}
	return true
}

func (a *API) post(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.headers {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req) //#nosec G704 -- the endpoint audit.api.url names, the admin's
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return statusError(resp.StatusCode)
	}
	return nil
}

// encode is batch in the endpoint's format: {"items": [...]}, or for
// Splunk's HEC one event object per record, back to back, the record's
// time its time (seconds since the epoch, milliseconds kept).
func (a *API) encode(batch []Record) ([]byte, error) {
	if a.format != config.AuditFormatSplunkHEC {
		return json.Marshal(map[string][]Record{"items": batch})
	}
	var buf bytes.Buffer
	for _, r := range batch {
		ev := hecEvent{
			Time: float64(r.Time.UnixMilli()) / 1000, Event: r,
			Index: a.hec.Index, Sourcetype: a.hec.Sourcetype, Source: a.hec.Source, Host: a.hec.Host,
		}
		line, err := json.Marshal(ev)
		if err != nil {
			return nil, err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// hecEvent is one event of Splunk's HTTP Event Collector.
type hecEvent struct {
	Time       float64 `json:"time"`
	Host       string  `json:"host,omitempty"`
	Source     string  `json:"source,omitempty"`
	Sourcetype string  `json:"sourcetype,omitempty"`
	Index      string  `json:"index,omitempty"`
	Event      Record  `json:"event"`
}

package config

import (
	"fmt"
	"net/url"
	"time"
)

// The audit backends.
const (
	AuditNone = "none"
	AuditFile = "file"
	AuditAPI  = "api"
)

// AuditConfig is the audit: block: where Kayra writes who asked for what
// and whether it was allowed, on every /check decision and every request
// to its own routes (internal/audit). Off (none) unless set.
type AuditConfig struct {
	// Backend is file, api or none (the default).
	Backend string `yaml:"backend"`
	// Reads audits get and list too: only writes and denials otherwise.
	Reads bool `yaml:"reads"`
	// File is the file backend's.
	File AuditFileConfig `yaml:"file"`
	// API is the api backend's.
	API AuditAPIConfig `yaml:"api"`
}

// AuditFileConfig is a file of JSON lines.
type AuditFileConfig struct {
	// Path is the file, appended to; "-" is stdout. SIGHUP reopens it,
	// for logrotate.
	Path string `yaml:"path"`
}

// AuditAPIConfig is an HTTP endpoint the records are POSTed to, in
// batches: {"items": [...]}.
type AuditAPIConfig struct {
	// URL receives the batches: https, or http on a loopback address.
	URL string `yaml:"url"`
	// Headers are sent as they are, ${VAR} replaced by the environment
	// variable VAR: Authorization: "Splunk ${SPLUNK_HEC_TOKEN}".
	Headers map[string]string `yaml:"headers"`
	// TLS is a CA to verify the endpoint with, and a client certificate.
	TLS AuditTLSConfig `yaml:"tls"`
	// Timeout bounds one POST: 5s when empty.
	Timeout string `yaml:"timeout"`
	// Batch is when a batch is sent: max_events records (100), or
	// max_wait after its first (1s).
	Batch AuditBatchConfig `yaml:"batch"`
	// Queue is how many records wait to be sent (10000): a record that
	// finds it full is dropped, and counted.
	Queue int `yaml:"queue"`
}

// AuditTLSConfig is the api backend's TLS: the endpoint's certificate is
// always verified, against CACert when set, the system's roots otherwise.
type AuditTLSConfig struct {
	CACert string `yaml:"cacert"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

// AuditBatchConfig is when a batch is sent.
type AuditBatchConfig struct {
	MaxEvents int    `yaml:"max_events"`
	MaxWait   string `yaml:"max_wait"`
}

// AuditAPISettings are the api backend's settings, defaults applied.
type AuditAPISettings struct {
	Timeout   time.Duration
	MaxEvents int
	MaxWait   time.Duration
	Queue     int
}

// Settings are a's settings, defaults applied.
func (a AuditAPIConfig) Settings() (AuditAPISettings, error) {
	s := AuditAPISettings{Timeout: 5 * time.Second, MaxEvents: 100, MaxWait: time.Second, Queue: 10000}
	for _, d := range []struct {
		name, value string
		into        *time.Duration
	}{{"audit.api.timeout", a.Timeout, &s.Timeout}, {"audit.api.batch.max_wait", a.Batch.MaxWait, &s.MaxWait}} {
		if d.value == "" {
			continue
		}
		v, err := time.ParseDuration(d.value)
		if err != nil || v <= 0 {
			return s, fmt.Errorf("%s %q: a positive duration, like 5s", d.name, d.value)
		}
		*d.into = v
	}
	if a.Batch.MaxEvents < 0 || a.Queue < 0 {
		return s, fmt.Errorf("audit.api: batch.max_events and queue are positive")
	}
	if a.Batch.MaxEvents > 0 {
		s.MaxEvents = a.Batch.MaxEvents
	}
	if a.Queue > 0 {
		s.Queue = a.Queue
	}
	return s, nil
}

// BackendName is a's backend, none when empty.
func (a AuditConfig) BackendName() string {
	if a.Backend == "" {
		return AuditNone
	}
	return a.Backend
}

func (a AuditConfig) validate() error {
	switch a.BackendName() {
	case AuditNone:
	case AuditFile:
		if a.File.Path == "" {
			return fmt.Errorf(`audit.file.path: a file, or "-" for stdout`)
		}
	case AuditAPI:
		u, err := url.Parse(a.API.URL)
		secure := u != nil && (u.Scheme == "https" || (u.Scheme == "http" && IsLoopback(u.Hostname())))
		if err != nil || u.Host == "" || !secure {
			return fmt.Errorf("audit.api.url %q: an https URL (http on a loopback address)", a.API.URL)
		}
		if (a.API.TLS.Cert == "") != (a.API.TLS.Key == "") {
			return fmt.Errorf("audit.api.tls: cert and key together")
		}
		if _, err := a.API.Settings(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("audit.backend %q: file, api or none", a.Backend)
	}
	return nil
}

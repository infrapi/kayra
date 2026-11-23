package config

import (
	"strings"
	"testing"
	"time"
)

func TestAuditValidate(t *testing.T) {
	for _, ok := range []AuditConfig{
		{},
		{Backend: "none"},
		{Backend: "file", File: AuditFileConfig{Path: "-"}},
		{Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com/ingest"}},
		{Backend: "api", API: AuditAPIConfig{URL: "http://127.0.0.1:9999/x", Timeout: "2s", Batch: AuditBatchConfig{MaxEvents: 10, MaxWait: "500ms"}}},
		{Backend: "api", API: AuditAPIConfig{URL: "https://splunk.example.com:8088/services/collector/event", Format: "splunk-hec",
			Headers: map[string]string{"Authorization": "Splunk ${SPLUNK_HEC_TOKEN}"}, SplunkHEC: SplunkHECConfig{Index: "kayra"}}},
	} {
		if err := ok.validate(); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
	for want, bad := range map[string]AuditConfig{
		"file, api or none":       {Backend: "syslog"},
		"audit.file.path":         {Backend: "file"},
		"an https URL":            {Backend: "api", API: AuditAPIConfig{URL: "http://siem.example.com"}},
		"cert and key":            {Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com", TLS: AuditTLSConfig{Cert: "c.pem"}}},
		"a positive duration":     {Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com", Timeout: "soon"}},
		"generic or splunk-hec":   {Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com", Format: "elastic"}},
		"Splunk <token>":          {Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com", Format: "splunk-hec", Headers: map[string]string{"Authorization": "Bearer x"}}},
		"format: splunk-hec only": {Backend: "api", API: AuditAPIConfig{URL: "https://siem.example.com", SplunkHEC: SplunkHECConfig{Index: "kayra"}}},
	} {
		if err := bad.validate(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", bad, err, want)
		}
	}
	s, _ := AuditAPIConfig{}.Settings()
	if s != (AuditAPISettings{Timeout: 5 * time.Second, MaxEvents: 100, MaxWait: time.Second, Queue: 10000}) {
		t.Errorf("defaults: %+v", s)
	}
}

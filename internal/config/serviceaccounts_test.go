package config

import (
	"strings"
	"testing"
	"time"
)

func TestServiceAccountDurations(t *testing.T) {
	d, err := ServiceAccountsConfig{}.Durations()
	if err != nil || d.Default != time.Hour || d.Max != 24*time.Hour {
		t.Fatalf("defaults: %+v %v", d, err)
	}
	d, err = ServiceAccountsConfig{TokenTTL: "5m", MaxTokenTTL: "2h"}.Durations()
	if err != nil || d.Default != 5*time.Minute || d.Max != 2*time.Hour {
		t.Fatalf("set: %+v %v", d, err)
	}
	for c, want := range map[ServiceAccountsConfig]string{
		{MaxTokenTTL: "48h"}:                "at most 24h0m0s",
		{TokenTTL: "3h", MaxTokenTTL: "2h"}: "more than max_token_ttl",
		{TokenTTL: "soon"}:                  "token_ttl \"soon\": a duration",
		{MaxTokenTTL: "-1h"}:                "max_token_ttl \"-1h\": a duration",
	} {
		if _, err := c.Durations(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: %v, want %q", c, err, want)
		}
	}
}

package config

import (
	"fmt"
	"time"
)

// EventsConfig is the events: block: events.<domain>, what happened to the
// APIs' resources, kept in etcd for TTL (internal/events).
type EventsConfig struct {
	// TTL is how long an event is kept after it was last seen: 168h when
	// empty.
	TTL string `yaml:"ttl"`
	// Stdout also writes each accepted event to stdout, a JSON line.
	Stdout bool `yaml:"stdout"`
	// Rate limits each reporter: per_second events (50), burst at once
	// (200). Over it, a 429 with Retry-After.
	Rate EventsRate `yaml:"rate"`
}

// EventsRate is a token bucket per reporter.
type EventsRate struct {
	PerSecond float64 `yaml:"per_second"`
	Burst     int     `yaml:"burst"`
}

// EventsSettings are the events' settings, defaults applied.
type EventsSettings struct {
	TTL       time.Duration
	Stdout    bool
	PerSecond float64
	Burst     int
}

// Settings are e's settings, defaults applied.
func (e EventsConfig) Settings() (EventsSettings, error) {
	s := EventsSettings{TTL: 168 * time.Hour, Stdout: e.Stdout, PerSecond: 50, Burst: 200}
	if e.TTL != "" {
		d, err := time.ParseDuration(e.TTL)
		if err != nil || d < time.Minute {
			return s, fmt.Errorf("events.ttl %q: a duration of a minute or more, like 168h", e.TTL)
		}
		s.TTL = d
	}
	if e.Rate.PerSecond < 0 || e.Rate.Burst < 0 {
		return s, fmt.Errorf("events.rate: per_second and burst are positive")
	}
	if e.Rate.PerSecond > 0 {
		s.PerSecond = e.Rate.PerSecond
	}
	if e.Rate.Burst > 0 {
		s.Burst = e.Rate.Burst
	}
	return s, nil
}

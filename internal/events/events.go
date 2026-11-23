// Package events serves events.<domain>: what happened to the APIs'
// resources, as Kubernetes' events.k8s.io. The APIs report them (infrapi/lib's
// recorder), Kayra keeps them in etcd for events.ttl after they were last
// seen, and serves them to whoever the namespace's RBAC lets read them.
// Best effort: unlike the audit, an event may be lost.
package events

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// API is the events group, events.<domain> (SetAPIDomain).
var API = "events.infrapi.io"

// SetAPIDomain names the group after Kayra's app.api_domain.
func SetAPIDomain(domain string) { API = "events." + domain }

// Resource is the group's one resource.
const Resource = "events"

// The types of an event.
const (
	Normal  = "Normal"
	Warning = "Warning"
)

// Limits of what an event holds.
const (
	MaxBatch   = 100
	maxReason  = 128
	maxNote    = 1024
	maxDetails = 4096
)

// Event is one event.
type Event struct {
	// ID is set by Kayra: a UUIDv7, the events sorting by reception.
	ID string `json:"id"`
	// ReceivedAt is set by Kayra.
	ReceivedAt time.Time `json:"received_at"`
	// Reporter is set by Kayra: the subject of the token that sent it, an
	// API's system:api:<group> say.
	Reporter string `json:"reporter"`
	// Regarding is the object it is about; its namespace the request's.
	Regarding Regarding `json:"regarding"`
	// Type is Normal or Warning.
	Type string `json:"type"`
	// Reason is PascalCase: VMCreated.
	Reason string `json:"reason"`
	// Note says more, for a human.
	Note string `json:"note,omitempty"`
	// Action is what was done: create, reboot.
	Action string `json:"action,omitempty"`
	// ReportingController is what reported it: the API's name, a worker's.
	ReportingController string `json:"reporting_controller"`
	// User is who asked, when someone did.
	User string `json:"user,omitempty"`
	// RequestID joins it to the request, and to its audit record.
	RequestID string `json:"request_id,omitempty"`
	// Details are the reporter's own, as it likes.
	Details map[string]any `json:"details,omitempty"`
	// Time is when it happened: ReceivedAt when empty.
	Time time.Time `json:"time"`
	// Series counts the same event seen again (PATCH by its reporter).
	Series *Series `json:"series,omitempty"`
}

// Regarding is the object an event is about.
type Regarding struct {
	API       string `json:"api"`
	Namespace string `json:"namespace,omitempty"`
	Resource  string `json:"resource"`
	Name      string `json:"name,omitempty"`
}

// Series is the same event seen again: how often, and when last.
type Series struct {
	Count        int       `json:"count"`
	LastObserved time.Time `json:"last_observed"`
}

var reason = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*$`)

// validate refuses an event without type, reason, regarding.resource or
// reporting_controller, a reason that is no PascalCase word, and one too
// big; namespace is the request's, regarding.namespace's when it says one.
func (e *Event) validate(namespace string) error {
	switch {
	case e.Type != Normal && e.Type != Warning:
		return fmt.Errorf("type %q: Normal or Warning", e.Type)
	case !reason.MatchString(e.Reason) || len(e.Reason) > maxReason:
		return fmt.Errorf("reason %q: a PascalCase word, like VMCreated", e.Reason)
	case e.Regarding.API == "" || e.Regarding.Resource == "":
		return fmt.Errorf("regarding: api and resource are required")
	case e.ReportingController == "":
		return fmt.Errorf("reporting_controller is required: what reports it, the API's name say")
	case len(e.Note) > maxNote:
		return fmt.Errorf("note: %d bytes at most", maxNote)
	case e.Regarding.Namespace != "" && e.Regarding.Namespace != namespace:
		return fmt.Errorf("regarding.namespace %q is not the request's, %q", e.Regarding.Namespace, namespace)
	}
	if e.Details != nil {
		if b, err := json.Marshal(e.Details); err != nil || len(b) > maxDetails {
			return fmt.Errorf("details: %d bytes of JSON at most", maxDetails)
		}
	}
	if e.Series != nil && e.Series.Count < 1 {
		return fmt.Errorf("series.count: 1 or more")
	}
	e.Regarding.Namespace = namespace
	return nil
}

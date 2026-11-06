package catalog

import (
	"net/http"
	"strings"
	"testing"
)

// TestApiRegistrationShortName confirms a registration's id is its long
// name, that short_name is an optional, unique single-label alias, and
// that a subscription can only ever name the long one.
func TestApiRegistrationShortName(t *testing.T) {
	engine, _ := newTestEngine(t)
	const regs = "/apis/catalog.example.com/v1/apiregistrations"

	w := doJSON(t, engine, http.MethodPost, regs, ApiRegistration{Name: "dev", Active: true})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("short name as id: status %d, want 400, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, regs, ApiRegistration{Name: "dev.example.com", ShortName: "dev", Active: true})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status %d, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, regs, ApiRegistration{Name: "other.example.com", ShortName: "dev"})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate short_name: status %d, want 409, body %s", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, regs, ApiRegistration{Name: "other.example.com", ShortName: "a.b"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("dotted short_name: status %d, want 400, body %s", w.Code, w.Body.String())
	}

	// Updating a registration keeping its own short_name is not a conflict.
	w = doJSON(t, engine, http.MethodPut, regs+"/dev.example.com", ApiRegistration{ShortName: "dev", Owner: "sre"})
	if w.Code != http.StatusOK {
		t.Fatalf("update keeping short_name: status %d, body %s", w.Code, w.Body.String())
	}

	subs := "/apis/subscription.example.com/v1/namespaces/" + testNamespace + "/subscriptions"
	w = doJSON(t, engine, http.MethodPost, subs, subscriptionCreateRequest{ApiName: "dev"})
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), `dev.example.com`) {
		t.Fatalf("subscribe by short name: status %d body %s, want 400 pointing at dev.example.com", w.Code, w.Body.String())
	}

	w = doJSON(t, engine, http.MethodPost, subs, subscriptionCreateRequest{ApiName: "dev.example.com"})
	if w.Code != http.StatusCreated {
		t.Fatalf("subscribe by long name: status %d, body %s", w.Code, w.Body.String())
	}
}

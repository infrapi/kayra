package catalog

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/infrapi/kayra/internal/config"
)

func testData() stepTemplateData {
	return stepTemplateData{Subscription: subscriptionTemplateData{
		Api: "compute", Namespace: "core", Platform: "sandbox", Region: "eu-west-1",
		CurrentSyncID: "old-id", ExpectedSyncID: "new-id",
	}}
}

func TestRunStepsRendersTemplatesAndSucceeds(t *testing.T) {
	var gotPath, gotBody, gotAuth, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method:   "post",
		Endpoint: srv.URL + "/api/v1/namespaces/{{ .Subscription.Namespace }}/sync",
		Data:     map[string]any{"sync_id": "{{ .Subscription.ExpectedSyncID }}"},
		Headers: map[string]config.HeaderValue{
			"Content-Type":  {Raw: "application/json"},
			"Authorization": {Type: "Bearer", Value: "tok-123"},
		},
		Timeout: "5s",
	}}

	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	if gotPath != "/api/v1/namespaces/core/sync" {
		t.Fatalf("path = %q, want templated namespace", gotPath)
	}
	if !strings.Contains(gotBody, `"sync_id":"new-id"`) {
		t.Fatalf("body = %q, want rendered sync_id", gotBody)
	}
	if gotAuth != "Bearer tok-123" {
		t.Fatalf("Authorization = %q, want %q", gotAuth, "Bearer tok-123")
	}
	if gotContentType != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
}

// TestRunStepsRendersNestedData confirms Data supports arbitrarily
// nested YAML shapes — not just a flat string map — and templates every
// string leaf regardless of depth. Mirrors GitLab's pipeline-create API,
// which takes "variables" as a list of {key, value} objects rather than
// a flat map.
func TestRunStepsRendersNestedData(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method:   "post",
		Endpoint: srv.URL,
		Data: map[string]any{
			"ref": "{{ .Subscription.Platform }}",
			"variables": []any{
				map[string]any{"key": "TG_KAYRA_TENANT_NAME", "value": "{{ .Subscription.Namespace }}"},
				map[string]any{"key": "TG_KAYRA_API_NAME", "value": "{{ .Subscription.Api }}"},
				map[string]any{"key": "PLUMBING_TERRAFORM_CHECK_MAX", "value": "50"},
			},
		},
		Timeout: "5s",
	}}

	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	if gotBody["ref"] != "sandbox" {
		t.Fatalf("ref = %v, want sandbox", gotBody["ref"])
	}
	variables, ok := gotBody["variables"].([]any)
	if !ok || len(variables) != 3 {
		t.Fatalf("variables = %v, want 3 entries", gotBody["variables"])
	}
	first, ok := variables[0].(map[string]any)
	if !ok || first["key"] != "TG_KAYRA_TENANT_NAME" || first["value"] != "core" {
		t.Fatalf("variables[0] = %v, want key=TG_KAYRA_TENANT_NAME value=core", variables[0])
	}
	third, ok := variables[2].(map[string]any)
	if !ok || third["value"] != "50" {
		t.Fatalf("variables[2] = %v, want value=50 (untemplated literal preserved)", variables[2])
	}
}

func TestRunStepsSyncFailureAbortsPipeline(t *testing.T) {
	var secondStepCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		secondStepCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{Method: "post", Endpoint: srv.URL + "/fail", Timeout: "5s"},
		{Method: "get", Endpoint: srv.URL + "/ok", Timeout: "5s"},
	}

	err := runSteps(steps, testData(), 0)
	if err == nil {
		t.Fatal("runSteps: want error, got nil")
	}
	if secondStepCalled.Load() {
		t.Fatal("second step ran even though the first (sync) step failed")
	}
}

func TestRunStepsAsyncFailureIgnoredAndContinues(t *testing.T) {
	var secondStepCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		secondStepCalled.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{Method: "post", Endpoint: srv.URL + "/fail", Timeout: "5s", Async: true},
		{Method: "get", Endpoint: srv.URL + "/ok", Timeout: "5s"},
	}

	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: want nil (async failure is ignored), got %v", err)
	}
	if !secondStepCalled.Load() {
		t.Fatal("second step never ran after the async first step's failure")
	}
}

func TestRunStepsAsyncTimesOutAndContinues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(AsyncStepAckTimeout + 500*time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{Method: "post", Endpoint: srv.URL + "/slow", Timeout: "30s", Async: true},
		{Method: "get", Endpoint: srv.URL + "/fast", Timeout: "5s"},
	}

	start := time.Now()
	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	elapsed := time.Since(start)
	// the async step's own 30s Timeout must never be honored — it's
	// capped at AsyncStepAckTimeout regardless.
	if elapsed > AsyncStepAckTimeout+2*time.Second {
		t.Fatalf("runSteps took %s, want roughly bounded by AsyncStepAckTimeout (%s)", elapsed, AsyncStepAckTimeout)
	}
}

func TestRunStepsPassesOutputsToNextStep(t *testing.T) {
	var gotNextPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trigger" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"pipeline_id": 42})
			return
		}
		gotNextPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{
			Method: "post", Endpoint: srv.URL + "/trigger", Timeout: "5s", Async: true,
			Outputs: map[string]string{"PipelineID": ".pipeline_id"},
		},
		{Method: "get", Endpoint: srv.URL + "/pipelines/{{ .Previous.Outputs.PipelineID }}", Timeout: "5s"},
	}

	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	if gotNextPath != "/pipelines/42" {
		t.Fatalf("second step path = %q, want /pipelines/42 (output threaded through)", gotNextPath)
	}
}

func TestRunStepsLastStepSuccessIsOverallSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{Method: "post", Endpoint: srv.URL, Timeout: "5s", Async: true},
	}
	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
}

// TestRunStepsLogsEveryStepResult confirms each step's own result — not
// just the pipeline's overall outcome — reaches the log: a successful
// sync step, and a failing async step whose error runSteps itself only
// logs that it's ignoring, never what the error actually was.
func TestRunStepsLogsEveryStepResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/fail" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{
		{Method: "post", Endpoint: srv.URL + "/fail", Timeout: "5s", Async: true},
		{Method: "get", Endpoint: srv.URL + "/ok", Timeout: "5s"},
	}

	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	if err := runSteps(steps, testData(), 7); err != nil {
		t.Fatalf("runSteps: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "step 0 async POST "+srv.URL+"/fail") || !strings.Contains(logged, "status 500") {
		t.Fatalf("log output missing step 0's own result: %s", logged)
	}
	if !strings.Contains(logged, "step 1 GET "+srv.URL+"/ok") || !strings.Contains(logged, "-> 200") {
		t.Fatalf("log output missing step 1's own result: %s", logged)
	}
	if !strings.Contains(logged, "lock_id=7") || !strings.Contains(logged, `sync_id="new-id"`) {
		t.Fatalf("log output missing lock_id/sync_id on every step: %s", logged)
	}
}

// withShortWaitPollInterval shortens WaitPollInterval for the duration of
// a test, so polling tests don't actually wait out the real 5s default.
func withShortWaitPollInterval(t *testing.T) {
	t.Helper()
	orig := WaitPollInterval
	WaitPollInterval = 20 * time.Millisecond
	t.Cleanup(func() { WaitPollInterval = orig })
}

// TestRunStepsWaitPollsUntilSuccess confirms a step with a wait condition
// keeps re-issuing its call — the status starts "running", only becoming
// "done" (a Successes value) after a few polls — rather than treating the
// first (still-running) response as the step's result.
func TestRunStepsWaitPollsUntilSuccess(t *testing.T) {
	withShortWaitPollInterval(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		status := "running"
		if n >= 3 {
			status = "done"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "result": 99})
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method: "get", Endpoint: srv.URL, Timeout: "5s",
		Wait: []config.WaitCondition{
			{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed", "canceled"}},
		},
		Outputs: map[string]string{"Result": ".result"},
	}}

	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	if calls.Load() < 3 {
		t.Fatalf("server was called %d times, want at least 3 (polled until done)", calls.Load())
	}
}

// TestRunStepsWaitFailsOnFailureValue confirms the step fails immediately
// — no further polling — the moment the response's key lands in Failures.
func TestRunStepsWaitFailsOnFailureValue(t *testing.T) {
	withShortWaitPollInterval(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "failed"})
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method: "get", Endpoint: srv.URL, Timeout: "5s",
		Wait: []config.WaitCondition{
			{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed", "canceled"}},
		},
	}}

	err := runSteps(steps, testData(), 0)
	if err == nil {
		t.Fatal("runSteps: want error for a Failures-value response, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("server was called %d times, want exactly 1 (failed on the first response)", calls.Load())
	}
}

// TestRunStepsWaitTimesOutWhenNeverResolved confirms a response that
// never lands in either Successes or Failures eventually fails the step
// once Timeout elapses, rather than polling forever.
func TestRunStepsWaitTimesOutWhenNeverResolved(t *testing.T) {
	withShortWaitPollInterval(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "running"})
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method: "get", Endpoint: srv.URL, Timeout: "100ms",
		Wait: []config.WaitCondition{
			{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed"}},
		},
	}}

	err := runSteps(steps, testData(), 0)
	if err == nil {
		t.Fatal("runSteps: want a timeout error, got nil")
	}
}

// TestRunStepsWaitIgnoredOnAsyncStep confirms an async step's Wait
// conditions are never evaluated — async is fire-and-forget by
// definition, so it can't also block until a terminal state.
func TestRunStepsWaitIgnoredOnAsyncStep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "running"})
	}))
	defer srv.Close()

	steps := []config.ReconcileStep{{
		Method: "get", Endpoint: srv.URL, Timeout: "5s", Async: true,
		Wait: []config.WaitCondition{
			{Key: ".status", Successes: []string{"done"}},
		},
	}}

	start := time.Now()
	if err := runSteps(steps, testData(), 0); err != nil {
		t.Fatalf("runSteps: %v", err)
	}
	if time.Since(start) > AsyncStepAckTimeout+time.Second {
		t.Fatalf("runSteps took %s, want bounded by AsyncStepAckTimeout — Wait must not apply to an async step", time.Since(start))
	}
}

func TestEvaluateWait(t *testing.T) {
	cases := []struct {
		name string
		body string
		cond []config.WaitCondition
		want waitOutcome
	}{
		{
			name: "single condition succeeds",
			body: `{"status":"done"}`,
			cond: []config.WaitCondition{{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed"}}},
			want: waitSucceeded,
		},
		{
			name: "single condition fails",
			body: `{"status":"failed"}`,
			cond: []config.WaitCondition{{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed"}}},
			want: waitFailed,
		},
		{
			name: "single condition pending",
			body: `{"status":"running"}`,
			cond: []config.WaitCondition{{Key: ".status", Successes: []string{"done"}, Failures: []string{"failed"}}},
			want: waitPending,
		},
		{
			name: "two conditions, both succeed",
			body: `{"status":"done","health":"ok"}`,
			cond: []config.WaitCondition{
				{Key: ".status", Successes: []string{"done"}},
				{Key: ".health", Successes: []string{"ok"}},
			},
			want: waitSucceeded,
		},
		{
			name: "two conditions, one still pending",
			body: `{"status":"done","health":"checking"}`,
			cond: []config.WaitCondition{
				{Key: ".status", Successes: []string{"done"}},
				{Key: ".health", Successes: []string{"ok"}},
			},
			want: waitPending,
		},
		{
			name: "two conditions, one fails short-circuits",
			body: `{"status":"running","health":"critical"}`,
			cond: []config.WaitCondition{
				{Key: ".status", Successes: []string{"done"}},
				{Key: ".health", Successes: []string{"ok"}, Failures: []string{"critical"}},
			},
			want: waitFailed,
		},
		{
			name: "key doesn't resolve is pending, not an error",
			body: `{"other":"value"}`,
			cond: []config.WaitCondition{{Key: ".status", Successes: []string{"done"}}},
			want: waitPending,
		},
		{
			name: "invalid JSON is pending",
			body: `not json`,
			cond: []config.WaitCondition{{Key: ".status", Successes: []string{"done"}}},
			want: waitPending,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := evaluateWait(c.cond, []byte(c.body))
			if got != c.want {
				t.Fatalf("evaluateWait = %v, want %v", got, c.want)
			}
		})
	}
}

func TestWalkJSONPath(t *testing.T) {
	var parsed any
	if err := json.Unmarshal([]byte(`{"status":"success","items":[{"id":7},{"id":9}],"nested":{"deep":"value"}}`), &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	cases := []struct {
		path    string
		want    string
		wantOK  bool
		comment string
	}{
		{".status", "success", true, "plain field"},
		{".nested.deep", "value", true, "nested field"},
		{".items[0].id", "7", true, "array index then field"},
		{".items[1].id", "9", true, "second array element"},
		{".missing", "", false, "absent field"},
		{".items[5].id", "", false, "out of range index"},
	}
	for _, c := range cases {
		got, ok := walkJSONPath(parsed, c.path)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Fatalf("%s: walkJSONPath(%q) = (%q, %v), want (%q, %v)", c.comment, c.path, got, ok, c.want, c.wantOK)
		}
	}
}

func TestReconcileRunsConfiguredStepsForMode(t *testing.T) {
	var gotSyncID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotSyncID = body["sync_id"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	repo := newTestRepo(t)
	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{
		Mode: map[string][]config.ReconcileStep{
			"api": {{
				Method: "post", Endpoint: srv.URL, Timeout: "5s",
				Data: map[string]any{"sync_id": "{{ .Subscription.ExpectedSyncID }}"},
			}},
		},
	})

	stack := ApiRegistration{Name: "compute", Mode: "api", SyncID: "sync-xyz"}
	if err := w.reconcile(stack, "core", Subscription{}, 0); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gotSyncID != "sync-xyz" {
		t.Fatalf("server received sync_id=%q, want sync-xyz", gotSyncID)
	}
}

func TestReconcileFallsBackToPlaceholderWithNoStepsConfigured(t *testing.T) {
	repo := newTestRepo(t)
	w := NewReconciler(repo, testDeployPlatform, testDeployRegion, config.ReconcilerConfig{})

	if err := w.reconcile(ApiRegistration{Name: "compute", Mode: "trigger"}, "core", Subscription{}, 0); err != nil {
		t.Fatalf("reconcile: want nil (placeholder success), got %v", err)
	}
}

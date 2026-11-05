package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/infrapi/kayra/internal/config"
)

// AsyncStepAckTimeout bounds how long an async step (config.ReconcileStep
// with Async: true) waits for a response before giving up and moving on
// regardless, even if the step's own Timeout is longer — an async step
// is "fire and forget": whatever happens to the call after this point is
// never waited on or allowed to block the rest of the pipeline.
const AsyncStepAckTimeout = 2 * time.Second

// WaitPollInterval is how often a step with Wait conditions re-issues its
// call while polling for one to resolve. A var, not a const, so tests can
// shorten it rather than actually waiting out a multi-second interval.
var WaitPollInterval = 5 * time.Second

// waitOutcome is what evaluateWait decided about a step's response.
type waitOutcome int

const (
	waitPending waitOutcome = iota
	waitSucceeded
	waitFailed
)

// stepTemplateData is what every step's Endpoint, Data value and Headers
// value renders as a Go text/template against.
type stepTemplateData struct {
	Subscription subscriptionTemplateData
	Previous     previousStepTemplateData
}

// subscriptionTemplateData is the "." Subscription half of
// stepTemplateData: everything about the subscription/api registration
// pair being reconciled that a step's endpoint/body/headers might need.
type subscriptionTemplateData struct {
	Api            string
	Namespace      string
	Platform       string
	Region         string
	CurrentSyncID  string
	ExpectedSyncID string
}

// previousStepTemplateData is the ".Previous" half: the immediately
// preceding step's own Outputs (empty for the first step, and whenever
// the preceding step produced none).
type previousStepTemplateData struct {
	Outputs map[string]string
}

// runSteps runs steps in order, threading each one's extracted Outputs
// into the next one's ".Previous.Outputs". Every step's result is logged
// (see runStep) regardless of what happens next. A non-async step's
// failure (a non-2xx response, a timeout, or a transport/template error)
// aborts the whole run; an async step's failure is only logged — the run
// always moves on to whatever comes next regardless of what happened to
// it. An empty steps list is trivially successful (nothing to do).
func runSteps(steps []config.ReconcileStep, data stepTemplateData, lockID int) error {
	data.Previous = previousStepTemplateData{Outputs: map[string]string{}}

	for i, step := range steps {
		outputs, err := runStep(i, step, data, lockID)
		if err != nil && !step.Async {
			return fmt.Errorf("step %d (%s %s): %w", i, step.Method, step.Endpoint, err)
		}
		if outputs == nil {
			outputs = map[string]string{}
		}
		data.Previous = previousStepTemplateData{Outputs: outputs}
	}
	return nil
}

// runStep renders step's endpoint/data/headers against data once, then
// either makes one HTTP call (the default) or — when step.Wait is set on
// a non-async step — repeats it every WaitPollInterval until a Wait
// condition resolves or step.Timeout elapses, extracting step.Outputs
// from whichever response ends up deciding the step. Either way, the
// step's own result is logged (index, method, rendered endpoint, async
// or not, how many attempts it took, status code or error, how long it
// took, and any outputs extracted) before returning — the one place that
// result is ever visible for an async step, since runSteps only logs
// that it's ignoring the error, not what the error was. Outputs are
// returned best-effort even when the call itself errors, since an async
// step's caller still wants whatever the response (if any arrived in
// time) offered.
func runStep(index int, step config.ReconcileStep, data stepTemplateData, lockID int) (outputs map[string]string, stepErr error) {
	start := time.Now()
	method := strings.ToUpper(step.Method)
	// endpoint defaults to the unrendered template, so the log below
	// still names the step usefully even if rendering itself is what
	// failed; it's overwritten with the real, rendered value the moment
	// that succeeds.
	endpoint := step.Endpoint
	var statusCode, attempts int

	defer func() {
		elapsed := time.Since(start)
		async := ""
		if step.Async {
			async = " async"
		}
		switch {
		case stepErr != nil:
			log.Printf("catalog: reconciler: lock_id=%d sync_id=%q step %d%s %s %s -> error after %d attempt(s), %s: %v (outputs=%v)",
				lockID, data.Subscription.ExpectedSyncID, index, async, method, endpoint, attempts, elapsed, stepErr, outputs)
		default:
			log.Printf("catalog: reconciler: lock_id=%d sync_id=%q step %d%s %s %s -> %d after %d attempt(s), %s (outputs=%v)",
				lockID, data.Subscription.ExpectedSyncID, index, async, method, endpoint, statusCode, attempts, elapsed, outputs)
		}
	}()

	rendered, err := renderTemplate(step.Endpoint, data)
	if err != nil {
		return nil, fmt.Errorf("render endpoint: %w", err)
	}
	endpoint = rendered

	var bodyBytes []byte
	if len(step.Data) > 0 {
		renderedData := make(map[string]any, len(step.Data))
		for key, value := range step.Data {
			rv, err := renderValue(value, data)
			if err != nil {
				return nil, fmt.Errorf("render data[%s]: %w", key, err)
			}
			renderedData[key] = rv
		}
		bodyBytes, err = json.Marshal(renderedData)
		if err != nil {
			return nil, fmt.Errorf("marshal data: %w", err)
		}
	}

	headers := make(map[string]string, len(step.Headers))
	for name, hv := range step.Headers {
		value, err := renderTemplate(hv.Render(), data)
		if err != nil {
			return nil, fmt.Errorf("render header %s: %w", name, err)
		}
		headers[name] = value
	}

	timeout, err := time.ParseDuration(step.Timeout)
	if err != nil {
		return nil, fmt.Errorf("parse timeout: %w", err)
	}
	if step.Async {
		timeout = min(timeout, AsyncStepAckTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if len(step.Wait) == 0 || step.Async {
		attempts = 1
		var respBody []byte
		statusCode, respBody, err = doHTTPRequest(ctx, method, endpoint, bodyBytes, headers)
		if err != nil {
			return nil, err
		}
		outputs = extractOutputs(step.Outputs, respBody)
		if statusCode < 200 || statusCode >= 300 {
			return outputs, fmt.Errorf("%s %s: status %d", method, endpoint, statusCode)
		}
		return outputs, nil
	}

	ticker := time.NewTicker(WaitPollInterval)
	defer ticker.Stop()
	for {
		attempts++
		code, respBody, err := doHTTPRequest(ctx, method, endpoint, bodyBytes, headers)
		if err == nil {
			statusCode = code
			outputs = extractOutputs(step.Outputs, respBody)
			switch evaluateWait(step.Wait, respBody) {
			case waitSucceeded:
				return outputs, nil
			case waitFailed:
				return outputs, fmt.Errorf("%s %s: wait condition reported failure (status %d)", method, endpoint, code)
			}
		}
		select {
		case <-ctx.Done():
			return outputs, fmt.Errorf("%s %s: timed out waiting for condition after %s", method, endpoint, step.Timeout)
		case <-ticker.C:
		}
	}
}

// doHTTPRequest sends one request built fresh from method/endpoint/
// bodyBytes/headers (a *http.Request can't be safely reused once its
// body has been read, so runStep's poll loop calls this anew each
// attempt) and returns the response's status code and body.
func doHTTPRequest(ctx context.Context, method, endpoint string, bodyBytes []byte, headers map[string]string) (int, []byte, error) {
	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, respBody, nil
}

// evaluateWait checks body against every condition in conditions: any
// single condition whose Key value lands in its own Failures fails the
// whole step immediately, without regard to the others. Otherwise, every
// condition's Key value must land in its own Successes for the overall
// result to be waitSucceeded; anything short of that — a condition still
// outstanding, a Key that doesn't resolve, a body that isn't valid JSON —
// is waitPending.
func evaluateWait(conditions []config.WaitCondition, body []byte) waitOutcome {
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return waitPending
	}

	allSucceeded := true
	for _, cond := range conditions {
		value, ok := walkJSONPath(parsed, cond.Key)
		if !ok {
			allSucceeded = false
			continue
		}
		if containsString(cond.Failures, value) {
			return waitFailed
		}
		if !containsString(cond.Successes, value) {
			allSucceeded = false
		}
	}
	if allSucceeded {
		return waitSucceeded
	}
	return waitPending
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// renderTemplate parses and executes text as a Go text/template against
// data. Every templated field (endpoint, each data value, each rendered
// header value) goes through this, so "{{ .Subscription.Api }}" and
// "{{ .Previous.Outputs.PipelineID }}" work anywhere in a step.
func renderTemplate(text string, data stepTemplateData) (string, error) {
	tmpl, err := template.New("step").Parse(text)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// renderValue templates every string reachable inside v, however deeply
// nested — v itself, or (recursively) every value of a map[string]any
// and every element of a []any — leaving every other type (numbers,
// bools, nil) untouched. This is what lets a ReconcileStep.Data entry be
// an arbitrary YAML shape (GitLab's pipeline-create "variables: [{key,
// value}, ...]", say) rather than only a flat string map, while still
// templating every leaf.
func renderValue(v any, data stepTemplateData) (any, error) {
	switch t := v.(type) {
	case string:
		return renderTemplate(t, data)
	case map[string]any:
		out := make(map[string]any, len(t))
		for key, value := range t {
			rv, err := renderValue(value, data)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			out[key] = rv
		}
		return out, nil
	case []any:
		out := make([]any, len(t))
		for i, value := range t {
			rv, err := renderValue(value, data)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			out[i] = rv
		}
		return out, nil
	default:
		return v, nil
	}
}

// extractOutputs pulls each named value out of body (parsed as JSON)
// per outputs' dot-path, skipping (not erroring on) any path that
// doesn't resolve — an output is best-effort, so a step whose response
// doesn't carry a field it names shouldn't abort reconciliation over it.
func extractOutputs(outputs map[string]string, body []byte) map[string]string {
	result := make(map[string]string, len(outputs))
	if len(outputs) == 0 {
		return result
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return result
	}

	for name, path := range outputs {
		if value, ok := walkJSONPath(parsed, path); ok {
			result[name] = value
		}
	}
	return result
}

// walkJSONPath navigates v by path — a simple dot path (".pipeline_id",
// ".items[0].id"), not a full JSONPath implementation: just object field
// and array index traversal, in that order within one segment.
func walkJSONPath(v any, path string) (string, bool) {
	path = strings.TrimPrefix(path, ".")
	if path != "" {
		for _, segment := range strings.Split(path, ".") {
			key, index, hasIndex := splitIndex(segment)
			if key != "" {
				m, ok := v.(map[string]any)
				if !ok {
					return "", false
				}
				if v, ok = m[key]; !ok {
					return "", false
				}
			}
			if hasIndex {
				arr, ok := v.([]any)
				if !ok || index < 0 || index >= len(arr) {
					return "", false
				}
				v = arr[index]
			}
		}
	}
	return stringify(v)
}

// splitIndex splits one path segment, e.g. "items[0]", into its key
// ("items") and index (0, hasIndex true); a plain segment like "id" has
// no index (hasIndex false, key is the segment itself).
func splitIndex(segment string) (key string, index int, hasIndex bool) {
	open := strings.IndexByte(segment, '[')
	if open < 0 {
		return segment, 0, false
	}
	closeIdx := strings.IndexByte(segment, ']')
	if closeIdx < open {
		return segment, 0, false
	}
	n, err := strconv.Atoi(segment[open+1 : closeIdx])
	if err != nil {
		return segment, 0, false
	}
	return segment[:open], n, true
}

// stringify renders a decoded JSON value as the plain string an Outputs
// entry should be: a string as-is, a number/bool in its natural form, a
// nested object/array re-encoded as JSON, nil as not-found.
func stringify(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		data, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(data), true
	}
}

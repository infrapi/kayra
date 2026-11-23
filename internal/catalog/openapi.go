package catalog

// OpenAPI specs of registered apis. Kayra knows nothing about the apps
// behind its registrations, so it learns what each one serves from the
// app itself: every infrapi/lib app serves its route table as an OpenAPI
// document under its group's root, reachable through the gateway as
// <gateway>/apis/<api>/<version>/-/openapi.json. The Reconciler fetches it on each
// sync (see Reconciler.ensureSpec) and stores it with the resources
// derived from it; discovery (GET /apis) and
// .../apiregistrations/{name}/openapi.json serve it from there.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/oidc"
	"github.com/infrapi/kayra/internal/store"
)

// MaxSpecBytes caps a fetched spec. etcd refuses values over 1.5 MiB by
// default; this leaves room for the derived resources stored next to it.
const MaxSpecBytes = 1 << 20

// ApiSpec is the last OpenAPI spec fetched for one registration.
type ApiSpec struct {
	// Api is the registration's name (its long name).
	Api string `json:"api"`
	// Version is the registration's version this spec was fetched for:
	// a registration moved to another version refetches it.
	Version string `json:"version"`
	// SyncID is the registration's sync_id this spec was fetched for: a
	// sync to a newer sync_id refetches it first.
	SyncID string `json:"sync_id"`
	// URL is where it was fetched from.
	URL string `json:"url"`
	// Resources are derived from Spec's paths (see DeriveResources).
	Resources []ApiResource `json:"resources"`
	// Spec is the document exactly as the app served it.
	Spec json.RawMessage `json:"spec"`
	// JWKS are the app's public keys, fetched with the spec when its
	// identity's jwks_from is spec (FetchJWKS).
	JWKS *oidc.JWKSet `json:"jwks,omitempty"`

	store.Timestamps
}

// ApiResource is one resource an api serves, as infrapi-cli api-resources
// lists it.
type ApiResource struct {
	// Name is the path past the api's version (and past
	// namespaces/{namespace} for a namespaced one), path parameters
	// dropped: "subscriptions", or "subscriptions/sync" for an action —
	// the same Resource infrapi/lib's auth derives for /check.
	Name       string   `json:"name"`
	Namespaced bool     `json:"namespaced"`
	Verbs      []string `json:"verbs"`
}

// Route is one method+path an api serves. Path parameters may be in
// OpenAPI form ({name}) or gin form (:name, *name).
type Route struct {
	Method string
	Path   string
}

// DeriveResources turns api's routes into resources, following the
// /apis/<api>/<version>/[namespaces/{namespace}/]<resource>[/{name}[/<action>]]
// convention every Kayra and infrapi/lib route uses. Verbs follow the
// HTTP method, as infrapi/lib's auth maps them: GET is "list" on a
// collection (the path ends on a name, .../environments/{environment}/modules
// included) and "get" on an item (it ends on a parameter),
// POST "create", PUT "update", PATCH "patch", DELETE "delete". Routes
// outside /apis/<api>/<version>/ are ignored, and so are the app's own
// operational endpoints under /apis/<api>/<version>/-/: health,
// metrics, docs are not resources.
func DeriveResources(api, version string, routes []Route) []ApiResource {
	prefix := "/apis/" + api + "/" + version + "/"
	type key struct {
		name       string
		namespaced bool
	}
	verbs := map[key]map[string]bool{}

	for _, rt := range routes {
		if !strings.HasPrefix(rt.Path, prefix) {
			continue
		}
		segs := strings.Split(strings.Trim(strings.TrimPrefix(rt.Path, prefix), "/"), "/")
		if segs[0] == "-" {
			continue
		}
		namespaced := false
		if len(segs) >= 3 && segs[0] == "namespaces" && isPathParam(segs[1]) {
			namespaced = true
			segs = segs[2:]
		}
		var names []string
		for _, s := range segs {
			if s != "" && !isPathParam(s) {
				names = append(names, s)
			}
		}
		// an item when the path ends on a parameter, as infrapi/lib's
		// auth.ParseResource tells them apart: the verb it asks Kayra for
		hasParam := isPathParam(segs[len(segs)-1])
		if len(names) == 0 {
			continue
		}
		k := key{strings.Join(names, "/"), namespaced}
		if verbs[k] == nil {
			verbs[k] = map[string]bool{}
		}
		verbs[k][verbFor(rt.Method, hasParam)] = true
	}

	out := make([]ApiResource, 0, len(verbs))
	for k, vs := range verbs {
		list := make([]string, 0, len(vs))
		for v := range vs {
			list = append(list, v)
		}
		sort.Strings(list)
		out = append(out, ApiResource{Name: k.name, Namespaced: k.namespaced, Verbs: list})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return !out[i].Namespaced && out[j].Namespaced
	})
	return out
}

func isPathParam(seg string) bool {
	return strings.HasPrefix(seg, "{") || strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*")
}

func verbFor(method string, hasParam bool) string {
	switch strings.ToUpper(method) {
	case http.MethodGet:
		if hasParam {
			return "get"
		}
		return "list"
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodPatch:
		return "patch"
	case http.MethodDelete:
		return "delete"
	default:
		return strings.ToLower(method)
	}
}

// specURL is where api's spec is served through the gateway: under its
// group's root, as infrapi/lib's server serves it.
func specURL(gatewayURL, api, version string) string {
	return strings.TrimRight(gatewayURL, "/") + "/apis/" + api + "/" + version + "/-/openapi.json"
}

// FetchSpec downloads api's OpenAPI spec through gatewayURL and derives
// its resources. It fails on anything but a 200 carrying a JSON object
// with an "openapi" version and a "paths" object, or on a document over
// MaxSpecBytes.
func FetchSpec(ctx context.Context, client *http.Client, gatewayURL, api, version string) (ApiSpec, error) {
	if gatewayURL == "" {
		return ApiSpec{}, fmt.Errorf("reconciler.gateway_url is not configured: the openapi spec is mandatory, so api %q can't be synced", api)
	}
	url := specURL(gatewayURL, api, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ApiSpec{}, fmt.Errorf("fetch openapi spec of %q: %w", api, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return ApiSpec{}, fmt.Errorf("fetch openapi spec of %q from %s: %w", api, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return ApiSpec{}, fmt.Errorf("fetch openapi spec of %q from %s: status %d", api, url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSpecBytes+1))
	if err != nil {
		return ApiSpec{}, fmt.Errorf("read openapi spec of %q from %s: %w", api, url, err)
	}
	if len(body) > MaxSpecBytes {
		return ApiSpec{}, fmt.Errorf("openapi spec of %q from %s is over %d bytes", api, url, MaxSpecBytes)
	}

	routes, err := specRoutes(body)
	if err != nil {
		return ApiSpec{}, fmt.Errorf("openapi spec of %q from %s: %w", api, url, err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, body); err != nil {
		return ApiSpec{}, fmt.Errorf("openapi spec of %q from %s: %w", api, url, err)
	}
	return ApiSpec{Api: api, Version: version, URL: url, Resources: DeriveResources(api, version, routes), Spec: compact.Bytes()}, nil
}

// jwksURL is where api serves its public keys through the gateway, beside
// its spec, as infrapi/lib's server serves them.
func jwksURL(gatewayURL, api, version string) string {
	return strings.TrimRight(gatewayURL, "/") + "/apis/" + api + "/" + version + "/-/jwks.json"
}

// MaxJWKSBytes caps a fetched key set.
const MaxJWKSBytes = 64 << 10

// FetchJWKS downloads api's public keys through gatewayURL: a JWK set of
// RSA or EC public keys (identity.CheckCredentials). An app that serves
// none gets an empty set, and no token: a 404, an empty set, or a 401 or
// 403, the answer of an app whose -/jwks.json is no open route (one
// without keys, or on a lib before it).
func FetchJWKS(ctx context.Context, client *http.Client, gatewayURL, api, version string) (*oidc.JWKSet, error) {
	url := jwksURL(gatewayURL, api, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch keys of %q: %w", api, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch keys of %q from %s: %w", api, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	none := &oidc.JWKSet{Keys: []oidc.JWK{}}
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		return none, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch keys of %q from %s: status %d", api, url, resp.StatusCode)
	}
	var set oidc.JWKSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxJWKSBytes)).Decode(&set); err != nil {
		return nil, fmt.Errorf("keys of %q from %s: %w", api, url, err)
	}
	if len(set.Keys) == 0 {
		return none, nil
	}
	if err := identity.CheckCredentials(&set, nil, nil); err != nil {
		return nil, fmt.Errorf("keys of %q from %s: %w", api, url, err)
	}
	return &set, nil
}

// specRoutes validates an OpenAPI document and lists its operations.
func specRoutes(doc []byte) ([]Route, error) {
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(doc, &spec); err != nil {
		return nil, fmt.Errorf("not a valid OpenAPI document: %w", err)
	}
	if spec.OpenAPI == "" || spec.Paths == nil {
		return nil, fmt.Errorf(`not a valid OpenAPI document: "openapi" and "paths" are required`)
	}
	var routes []Route
	for path, ops := range spec.Paths {
		for method := range ops {
			switch strings.ToUpper(method) {
			case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
				routes = append(routes, Route{Method: method, Path: path})
			}
		}
	}
	return routes, nil
}

// --- storage ---

func (r *Repository) PutApiSpec(platform, region string, spec *ApiSpec) error {
	return store.PutObject(r.store, r.keys.ApiSpec(platform, region, spec.Api), spec)
}

func (r *Repository) GetApiSpec(platform, region, name string) (ApiSpec, error) {
	var spec ApiSpec
	err := store.GetJSON(r.store, r.keys.ApiSpec(platform, region, name), &spec)
	return spec, err
}

func (r *Repository) DeleteApiSpec(platform, region, name string) error {
	if err := r.store.Delete(r.keys.ApiSpec(platform, region, name)); err != nil && err != store.ErrNotFound {
		return fmt.Errorf("catalog: delete openapi spec %s/%s/%s: %w", platform, region, name, err)
	}
	return nil
}

// ApiClient is api's registration as a client of the token endpoint
// (client_credentials): its uid, and what authenticates it, the keys of
// its identity (pinned, or its app's from its spec) and its federated
// credentials. store.ErrNotFound when it is not registered here, or has
// no identity.
func (r *Repository) ApiClient(platform, region, api string) (uid string, keys []oidc.JWK, federated []identity.FederatedCredential, err error) {
	reg, err := r.GetClusterApiRegistration(platform, region, api)
	if err != nil {
		return "", nil, nil, err
	}
	if reg.Identity == nil {
		return "", nil, nil, store.ErrNotFound
	}
	switch {
	case reg.Identity.JWKS != nil:
		keys = reg.Identity.JWKS.Keys
	case reg.KeysFromSpec():
		// none until the reconciler fetched them: no token yet
		if spec, err := r.GetApiSpec(platform, region, api); err == nil && spec.JWKS != nil {
			keys = spec.JWKS.Keys
		}
	}
	return reg.UID, keys, reg.Identity.FederatedCredentials, nil
}

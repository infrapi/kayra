package rbac

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/infrapi/kayra/api"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// A user's personal access tokens, /apis/authorization.infrapi.io/v1/
// tokens: created, listed, read and revoked by their public id. Every
// token expires, and may be scoped to some APIs and verbs, on top of what
// its user may do. Another user's are the cluster RBAC's token managers'
// (PATOptions.CanManageOthers), by ?user=.

// CreateToken creates a personal access token of the caller, a user: its
// secret is in the answer, never again.
func (s *Server) CreateToken(ctx context.Context, body api.Token) (api.Token, error) {
	const origin = "tokenapi.Create"
	o := s.o.PATs
	ac, err := Caller(ctx, origin)
	if err != nil {
		return api.Token{}, err
	}
	switch {
	case identity.IsReserved(ac.UserID):
		return api.Token{}, liberrors.New(http.StatusForbidden, origin, "%s is not a user: only a user gets a personal access token", ac.UserID).
			WithSolution("ask the service account's token action for a new token")
	case ac.TokenID != "":
		return api.Token{}, liberrors.New(http.StatusForbidden, origin, "a personal access token creates no other").
			WithSolution("log in (infrapi-cli auth login), then create it")
	}

	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 64 {
		return api.Token{}, liberrors.New(http.StatusBadRequest, origin, "name: what the token is for, 64 characters at most, like laptop")
	}
	ttl := o.TTLs.Default
	if body.ExpiresIn != "" {
		if ttl, err = time.ParseDuration(body.ExpiresIn); err != nil || ttl <= 0 {
			return api.Token{}, liberrors.New(http.StatusBadRequest, origin, "expires_in %q: a duration, like 720h", body.ExpiresIn)
		}
	}
	if ttl > o.TTLs.Max {
		return api.Token{}, liberrors.New(http.StatusBadRequest, origin, "expires_in %s: more than the %s a token may last", ttl, o.TTLs.Max)
	}
	var scope *gcrypto.PatScope
	if sc := body.Scope; sc.APIs != nil || sc.Verbs != nil {
		scope = &gcrypto.PatScope{Apis: sc.APIs, Verbs: sc.Verbs}
		if len(scope.Apis) == 0 || len(scope.Verbs) == 0 || slices.Contains(scope.Apis, "") || slices.Contains(scope.Verbs, "") {
			return api.Token{}, liberrors.New(http.StatusBadRequest, origin, "scope: apis and verbs, neither empty, each wildcardable with \"*\"").
				WithSolution(`like {"apis": ["compute.infrapi.io"], "verbs": ["get", "list"]}`)
		}
	}

	secret, err := gcrypto.GenerateToken()
	if err != nil {
		return api.Token{}, internal(err, origin)
	}
	now := o.Now().UTC().Truncate(time.Second)
	record := gcrypto.PatRecord{
		ID:            strings.ToLower(rand.Text()),
		Name:          name,
		UserID:        ac.UserID,
		Authorization: ac.Authorization,
		Provider:      ac.Provider,
		CreatedAt:     now.Unix(),
		ExpiresAt:     now.Add(ttl).Unix(),
		Scope:         scope,
	}
	// a claims-backed authorization backend has no directory to resolve
	// the groups from later: they are the token's, as they are now
	if o.Config.Authorizations[ac.Authorization].Claims != nil {
		record.SnapshotGroups = ac.Groups
		record.SnapshotAttributes = ac.Attributes
	}
	data, err := gcrypto.EncryptRecord(o.Pub, record)
	if err != nil {
		return api.Token{}, internal(err, origin)
	}
	hash := gcrypto.HashToken(secret)
	entry := gcrypto.PatIndexEntry{ID: record.ID, Name: record.Name, UserID: record.UserID, Hash: hash,
		CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, Scope: record.Scope}
	index, err := json.Marshal(entry)
	if err != nil {
		return api.Token{}, internal(err, origin)
	}
	// the record by the secret's hash, what the authenticator looks up;
	// the index by user and id, what the routes list and revoke
	if err := o.Store.PutTTL(o.Keys.PatToken(hash), data, ttl); err != nil {
		return api.Token{}, internal(err, origin)
	}
	if err := o.Store.PutTTL(o.Keys.PatIndex(record.UserID, record.ID), index, ttl); err != nil {
		return api.Token{}, internal(err, origin)
	}
	t := tokenOf(entry)
	t.Token = secret
	return t, nil
}

// ListTokens lists a user's tokens, oldest first, without their secret.
func (s *Server) ListTokens(ctx context.Context, user string) ([]api.Token, error) {
	const origin = "tokenapi.List"
	o := s.o.PATs
	user, err := s.whose(ctx, user, "list", origin)
	if err != nil {
		return nil, err
	}
	raw, err := o.Store.List(o.Keys.PatIndexPrefix(user))
	if err != nil {
		return nil, internal(err, origin)
	}
	tokens := []api.Token{}
	for _, data := range raw {
		var e gcrypto.PatIndexEntry
		if err := json.Unmarshal(data, &e); err != nil {
			return nil, internal(err, origin)
		}
		tokens = append(tokens, tokenOf(e))
	}
	slices.SortFunc(tokens, func(a, b api.Token) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return tokens, nil
}

// GetToken is one of a user's tokens, without its secret.
func (s *Server) GetToken(ctx context.Context, id, user string) (api.Token, error) {
	const origin = "tokenapi.Get"
	e, _, err := s.entry(ctx, id, user, "get", origin)
	if err != nil {
		return api.Token{}, err
	}
	return tokenOf(e), nil
}

// DeleteToken revokes one of a user's tokens: the authenticator no longer
// finds it.
func (s *Server) DeleteToken(ctx context.Context, id, user string) error {
	const origin = "tokenapi.Delete"
	o := s.o.PATs
	e, key, err := s.entry(ctx, id, user, "delete", origin)
	if err != nil {
		return err
	}
	if err := errors.Join(o.Store.Delete(o.Keys.PatToken(e.Hash)), o.Store.Delete(key)); err != nil {
		return internal(err, origin)
	}
	return nil
}

// entry is the index entry of user's token id, and its key.
func (s *Server) entry(ctx context.Context, id, user, verb, origin string) (gcrypto.PatIndexEntry, string, error) {
	o := s.o.PATs
	var e gcrypto.PatIndexEntry
	user, err := s.whose(ctx, user, verb, origin)
	if err != nil {
		return e, "", err
	}
	key := o.Keys.PatIndex(user, id)
	if err := store.GetJSON(o.Store, key, &e); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return e, "", liberrors.New(http.StatusNotFound, origin, "token %q not found", id)
		}
		return e, "", internal(err, origin)
	}
	return e, key, nil
}

// whose is the user whose tokens a request is about: the caller's, or
// user's (?user=) when the caller may manage others'.
func (s *Server) whose(ctx context.Context, user, verb, origin string) (string, error) {
	ac, err := Caller(ctx, origin)
	if err != nil {
		return "", err
	}
	if user == "" || user == ac.UserID {
		return ac.UserID, nil
	}
	if s.o.PATs.CanManageOthers == nil || !s.o.PATs.CanManageOthers(ac, verb) {
		return "", liberrors.New(http.StatusForbidden, origin, "not authorized to %s another user's tokens", verb)
	}
	return user, nil
}

// tokenOf is a token's index entry as the API shows it.
func tokenOf(e gcrypto.PatIndexEntry) api.Token {
	t := api.Token{ID: e.ID, Name: e.Name, User: e.UserID,
		CreatedAt: time.Unix(e.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(e.ExpiresAt, 0).UTC()}
	if e.Scope != nil {
		t.Scope = api.TokenScope{APIs: e.Scope.Apis, Verbs: e.Scope.Verbs}
	}
	if e.LastUsedAt != 0 {
		t.LastUsedAt = time.Unix(e.LastUsedAt, 0).UTC()
	}
	return t
}

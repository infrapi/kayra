// Package tokenapi serves a user's personal access tokens at
// /apis/authorization.infrapi.io/v1/tokens: created, listed and revoked by
// their public id. Every token expires, and may be scoped to some APIs and
// verbs, on top of what its user may do.
package tokenapi

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/identity"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Options configure the token routes.
type Options struct {
	// Root is the authorization API's: /apis/authorization.infrapi.io/v1.
	Root  string
	Store store.Store
	Keys  store.Keys
	// Pub encrypts the token records.
	Pub *rsa.PublicKey
	// Config tells a claims-backed authorization backend, whose groups are
	// snapshotted into the record.
	Config *gconfig.Config
	// TTLs are a token's default and longest lifetimes.
	TTLs gconfig.PatDurations
	// CanManageOthers tells whether the caller may list (verb list) or
	// revoke (delete) another user's tokens: never when nil.
	CanManageOthers func(ac *middleware.AuthContext, verb string) bool
	// Now is the clock: time.Now when nil.
	Now func() time.Time
}

// createRequest is the body of POST .../tokens.
type createRequest struct {
	// Name says what the token is for: laptop, ci.
	Name string `json:"name"`
	// ExpiresIn is its lifetime, a Go duration: the default when empty.
	ExpiresIn string `json:"expires_in"`
	// Scope narrows it: everything its user may do when nil.
	Scope *gcrypto.PatScope `json:"scope"`
}

// Token is a token as listed: never its secret.
type Token struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	User       string            `json:"user"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Scope      *gcrypto.PatScope `json:"scope,omitempty"`
	LastUsedAt *time.Time        `json:"last_used_at,omitempty"`
}

// created is the answer to a creation: the token, once.
type created struct {
	Token
	Secret string `json:"token"`
}

// RegisterRoutes mounts the token routes at Root/tokens behind gate
// (normally middleware.Authenticator): a user's own tokens, or another
// user's (?user=) for a caller CanManageOthers lets.
//
// A token is created only by a user logged in, never by a personal access
// token (no token begets a longer or wider one) nor by one of Kayra's own
// identities (a service account's tokens are its token action's).
func RegisterRoutes(r gin.IRouter, gate gin.HandlerFunc, o Options) {
	if o.Now == nil {
		o.Now = time.Now
	}
	base := o.Root + "/tokens"

	r.POST(base, gate, func(c *gin.Context) {
		const origin = "tokenapi.Create"
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, origin, "not authenticated"))
			return
		}
		switch {
		case identity.IsReserved(ac.UserID):
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, origin, "%s is not a user: only a user gets a personal access token", ac.UserID).
				WithSolution("ask the service account's token action for a new token"))
			return
		case ac.TokenID != "":
			httpapi.Fail(c, liberrors.New(http.StatusForbidden, origin, "a personal access token creates no other").
				WithSolution("log in (infrapi-cli auth login), then create it"))
			return
		}

		var req createRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusBadRequest, origin, ""))
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || len(req.Name) > 64 {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "name: what the token is for, 64 characters at most, like laptop"))
			return
		}
		ttl := o.TTLs.Default
		if req.ExpiresIn != "" {
			var err error
			if ttl, err = time.ParseDuration(req.ExpiresIn); err != nil || ttl <= 0 {
				httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "expires_in %q: a duration, like 720h", req.ExpiresIn))
				return
			}
		}
		if ttl > o.TTLs.Max {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "expires_in %s: more than the %s a token may last", ttl, o.TTLs.Max))
			return
		}
		if s := req.Scope; s != nil && (len(s.Apis) == 0 || len(s.Verbs) == 0 || slices.Contains(s.Apis, "") || slices.Contains(s.Verbs, "")) {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, origin, "scope: apis and verbs, neither empty, each wildcardable with \"*\"").
				WithSolution(`like {"apis": ["compute.infrapi.io"], "verbs": ["get", "list"]}`))
			return
		}

		secret, err := gcrypto.GenerateToken()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		now := o.Now().UTC().Truncate(time.Second)
		record := gcrypto.PatRecord{
			ID:            strings.ToLower(rand.Text()),
			Name:          req.Name,
			UserID:        ac.UserID,
			Authorization: ac.Authorization,
			Provider:      ac.Provider,
			CreatedAt:     now.Unix(),
			ExpiresAt:     now.Add(ttl).Unix(),
			Scope:         req.Scope,
		}
		if o.Config.Authorizations[ac.Authorization].Claims != nil {
			record.SnapshotGroups = ac.Groups
			record.SnapshotAttributes = ac.Attributes
		}
		data, err := gcrypto.EncryptRecord(o.Pub, record)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		hash := gcrypto.HashToken(secret)
		entry := gcrypto.PatIndexEntry{ID: record.ID, Name: record.Name, UserID: record.UserID, Hash: hash,
			CreatedAt: record.CreatedAt, ExpiresAt: record.ExpiresAt, Scope: record.Scope}
		index, err := json.Marshal(entry)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		// both expire with the token
		if err := o.Store.PutTTL(o.Keys.PatToken(hash), data, ttl); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		if err := o.Store.PutTTL(o.Keys.PatIndex(record.UserID, record.ID), index, ttl); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.JSON(http.StatusCreated, created{Token: tokenOf(entry), Secret: secret})
	})

	r.GET(base, gate, func(c *gin.Context) {
		const origin = "tokenapi.List"
		user, ok := whose(c, o, "list", origin)
		if !ok {
			return
		}
		raw, err := o.Store.List(o.Keys.PatIndexPrefix(user))
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		tokens := []Token{}
		for _, data := range raw {
			var e gcrypto.PatIndexEntry
			if err := json.Unmarshal(data, &e); err != nil {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
				return
			}
			tokens = append(tokens, tokenOf(e))
		}
		slices.SortFunc(tokens, func(a, b Token) int { return a.CreatedAt.Compare(b.CreatedAt) })
		c.JSON(http.StatusOK, tokens)
	})

	r.DELETE(base+"/:id", gate, func(c *gin.Context) {
		const origin = "tokenapi.Delete"
		user, ok := whose(c, o, "delete", origin)
		if !ok {
			return
		}
		id := c.Param("id")
		key := o.Keys.PatIndex(user, id)
		var e gcrypto.PatIndexEntry
		if err := store.GetJSON(o.Store, key, &e); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				httpapi.Fail(c, liberrors.New(http.StatusNotFound, origin, "token %q not found", id))
			} else {
				httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			}
			return
		}
		if err := errors.Join(o.Store.Delete(o.Keys.PatToken(e.Hash)), o.Store.Delete(key)); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, origin, ""))
			return
		}
		c.Status(http.StatusNoContent)
	})
}

// whose is the user whose tokens the request is about: the caller's, or
// ?user='s when the caller may manage another's (verb).
func whose(c *gin.Context, o Options, verb, origin string) (string, bool) {
	ac, ok := middleware.GetAuth(c)
	if !ok {
		httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, origin, "not authenticated"))
		return "", false
	}
	user := c.Query("user")
	if user == "" || user == ac.UserID {
		return ac.UserID, true
	}
	if o.CanManageOthers == nil || !o.CanManageOthers(ac, verb) {
		httpapi.Fail(c, liberrors.New(http.StatusForbidden, origin, "not authorized to %s another user's tokens", verb))
		return "", false
	}
	return user, true
}

// Token is the entry as listed.
func tokenOf(e gcrypto.PatIndexEntry) Token {
	t := Token{ID: e.ID, Name: e.Name, User: e.UserID, Scope: e.Scope,
		CreatedAt: time.Unix(e.CreatedAt, 0).UTC(), ExpiresAt: time.Unix(e.ExpiresAt, 0).UTC()}
	if e.LastUsedAt != 0 {
		used := time.Unix(e.LastUsedAt, 0).UTC()
		t.LastUsedAt = &used
	}
	return t
}

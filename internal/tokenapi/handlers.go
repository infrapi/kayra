// Package tokenapi issues personal access tokens: opaque, not JWTs, so
// their content is never visible from the etcd record alone — the spec's
// "Tokens" section.
package tokenapi

import (
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	gconfig "github.com/infrapi/kayra/internal/config"
	gcrypto "github.com/infrapi/kayra/internal/crypto"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// createRequest is the only supported body today: the spec's "for now we
// only support personal => pat" — no scoping, no type selection.
type createRequest struct {
	Type string `json:"type"`
}

// RegisterRoutes mounts POST /api/v1/tokens behind gate (normally
// middleware.Authenticator): the caller must already be authenticated by
// any configured provider, and the PAT it receives always inherits every
// role of every group it is currently a member of — "the token will
// inherit all roles where I'm a member of group", resolved live at use
// time rather than snapshotted here... with one exception: when the
// caller's own ac.Authorization names a claims-backed authorizations.<name>
// entry (see config.ClaimsAuthzConfig), there is no directory left to
// re-query later by bare user id, so the groups/attributes this same
// request already resolved are captured into the record now — see
// PatRecord.SnapshotGroups/SnapshotAttributes and
// middleware.resolvePAT. cfg is consulted only to tell the two cases
// apart.
func RegisterRoutes(r gin.IRouter, gate gin.HandlerFunc, s store.Store, keys store.Keys, pub *rsa.PublicKey, cfg *gconfig.Config) {
	r.POST("/api/v1/tokens", gate, func(c *gin.Context) {
		ac, ok := middleware.GetAuth(c)
		if !ok {
			httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "tokenapi.Create", "not authenticated"))
			return
		}

		var req createRequest
		_ = c.ShouldBindJSON(&req)
		if req.Type == "" {
			req.Type = "pat"
		}
		if req.Type != "pat" {
			httpapi.Fail(c, liberrors.New(http.StatusBadRequest, "tokenapi.Create", "unsupported token type %q, only %q is supported today", req.Type, "pat"))
			return
		}

		token, err := gcrypto.GenerateToken()
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "tokenapi.Create", ""))
			return
		}

		record := gcrypto.PatRecord{
			UserID:        ac.UserID,
			Authorization: ac.Authorization,
			Provider:      ac.Provider,
			CreatedAt:     time.Now().Unix(),
		}
		if cfg.Authorizations[ac.Authorization].Claims != nil {
			record.SnapshotGroups = ac.Groups
			record.SnapshotAttributes = ac.Attributes
		}

		data, err := gcrypto.EncryptRecord(pub, record)
		if err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "tokenapi.Create", ""))
			return
		}

		if err := s.Put(keys.PatToken(gcrypto.HashToken(token)), data); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "tokenapi.Create", ""))
			return
		}

		c.JSON(http.StatusCreated, gin.H{"type": "pat", "token": token})
	})
}

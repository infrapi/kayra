package oauth2server

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// lockWait bounds how long a refresh waits for another use of its token.
const lockWait = 5 * time.Second

// lock serializes the uses of a refresh token: this process's mutex, then
// the store's lock when it has one (etcd's, every replica's). The etcd
// mutex rides the store's one session, so two requests of one replica
// would both hold it: the process's mutex orders those. release frees both.
func (s *Server) lock(ctx context.Context, h string) (release func(), err error) {
	s.mu.Lock()
	locker, ok := s.store.(store.JobLocker)
	if !ok {
		return s.mu.Unlock, nil
	}
	ctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	for {
		got, free, err := locker.TryLock(ctx, s.key("locks", h))
		if err != nil {
			s.mu.Unlock()
			return nil, fmt.Errorf("lock the refresh token: %w", err)
		}
		if got {
			return func() { _ = free(); s.mu.Unlock() }, nil
		}
		select {
		case <-ctx.Done():
			s.mu.Unlock()
			return nil, fmt.Errorf("the refresh token is in use: try again")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Session is a login: its refresh tokens, renewed one by one, and the
// access tokens issued with them.
type Session struct {
	ID       string    `json:"id"`
	UserID   string    `json:"user_id"`
	ClientID string    `json:"client_id"`
	Created  time.Time `json:"created_at"`
	LastUsed time.Time `json:"last_used_at"`
	Expires  time.Time `json:"expires_at"`
}

// sessions are the logins not revoked: user's, every one's when "".
func (s *Server) sessions(user string) ([]Session, error) {
	prefix := s.prefix + "/families/"
	entries, err := s.store.List(prefix)
	if err != nil {
		return nil, err
	}
	out := []Session{}
	for key, data := range entries {
		var f family
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, err
		}
		// its refresh token unused past refresh_token_idle: the login is over
		expires := f.Created.Add(s.ttl.Refresh)
		if !f.LastUsed.IsZero() {
			expires = minTime(expires, f.LastUsed.Add(s.ttl.Idle))
		}
		if f.Revoked || user != "" && f.UserID != user || !expires.After(s.now()) {
			continue
		}
		out = append(out, Session{ID: strings.TrimPrefix(key, prefix), UserID: f.UserID, ClientID: f.Client,
			Created: f.Created, LastUsed: f.LastUsed, Expires: expires})
	}
	// the latest used first, then the latest created; the id breaks ties
	slices.SortFunc(out, func(a, b Session) int {
		return cmp.Or(b.LastUsed.Compare(a.LastUsed), b.Created.Compare(a.Created), strings.Compare(a.ID, b.ID))
	})
	return out, nil
}

// forUser is the user a request's ?user names: the caller themselves when
// it names none; another, when the cluster RBAC grants the caller verb on
// sessions (CanManageSessions: the sysadmin, a delegate).
func (s *Server) forUser(c *gin.Context, verb string) (string, bool) {
	ac, ok := middleware.GetAuth(c)
	if !ok {
		httpapi.Fail(c, liberrors.New(http.StatusUnauthorized, "oauth2server.Sessions", "not authenticated"))
		return "", false
	}
	user := c.Query("user")
	if user == "" || user == ac.UserID {
		return ac.UserID, true
	}
	if s.CanManageSessions == nil || !s.CanManageSessions(ac, verb) {
		httpapi.Fail(c, liberrors.New(http.StatusForbidden, "oauth2server.Sessions",
			"your cluster roles do not grant %q on sessions: only your own", verb))
		return "", false
	}
	return user, true
}

// listSessions are a user's logins: the caller's, or ?user's.
func (s *Server) listSessions(c *gin.Context) {
	user, ok := s.forUser(c, "list")
	if !ok {
		return
	}
	out, err := s.sessions(user)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "oauth2server.ListSessions", ""))
		return
	}
	c.JSON(http.StatusOK, out)
}

// revokeSessions revokes every login of a user: the caller's, or ?user's.
func (s *Server) revokeSessions(c *gin.Context) {
	user, ok := s.forUser(c, "delete")
	if !ok {
		return
	}
	out, err := s.sessions(user)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "oauth2server.RevokeSessions", ""))
		return
	}
	for _, sess := range out {
		if err := s.revokeFamily(sess.ID); err != nil {
			httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "oauth2server.RevokeSessions", ""))
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"revoked": len(out)})
}

// revokeSession revokes one login: the caller's own, or anyone's for whom
// the cluster RBAC grants delete on sessions.
func (s *Server) revokeSession(c *gin.Context) {
	ac, _ := middleware.GetAuth(c)
	var f family
	ok, err := s.get("families", c.Param("id"), &f)
	if err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "oauth2server.RevokeSession", ""))
		return
	}
	// another's session is not found, unless the caller may manage it
	mine := ok && ac != nil && f.UserID == ac.UserID
	if !ok || !mine && (s.CanManageSessions == nil || !s.CanManageSessions(ac, "delete")) {
		httpapi.Fail(c, liberrors.New(http.StatusNotFound, "oauth2server.RevokeSession", "no session %q of yours", c.Param("id")))
		return
	}
	if err := s.revokeFamily(c.Param("id")); err != nil {
		httpapi.Fail(c, liberrors.Wrap(err, http.StatusInternalServerError, "oauth2server.RevokeSession", ""))
		return
	}
	c.Status(http.StatusNoContent)
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

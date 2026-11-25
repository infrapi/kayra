package apiserver

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/infrapi/kayra/internal/audit"
	"github.com/infrapi/kayra/internal/httpapi"
	"github.com/infrapi/kayra/internal/middleware"
	libapi "github.com/infrapi/lib/pkg/api"
	libauth "github.com/infrapi/lib/pkg/auth"
	liberrors "github.com/infrapi/lib/pkg/errors"
	libserver "github.com/infrapi/lib/pkg/server"
)

// Option adjusts what Build builds.
type Option func(*options)

type options struct {
	auditor *audit.Auditor
}

// WithAudit writes the audit to auditor: /check's decisions and the
// requests to Kayra's own routes. None without it.
func WithAudit(auditor *audit.Auditor) Option {
	return func(o *options) { o.auditor = auditor }
}

// sessionsPath is the authorization server's sessions, audited with
// Kayra's own groups.
const sessionsPath = "/oauth2/sessions"

// auditRequests audits each request to Kayra's own routes once served
// (stage request): its groups under roots, and the sessions. Not their -/
// routes, nor /check, which audits its own decision. Under quiet, the events'
// root, only denials: an event is not worth an audit record.
func auditRequests(auditor *audit.Auditor, roots []string, check, quiet string) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		ours := strings.HasPrefix(path, sessionsPath)
		for _, root := range roots {
			ours = ours || strings.HasPrefix(path, root+"/")
		}
		if !ours || path == check || strings.Contains(path, "/-/") {
			c.Next()
			return
		}
		c.Next()
		r := requestRecord(c)
		if strings.HasPrefix(path, quiet) && r.Allowed {
			return
		}
		auditor.Record(r)
	}
}

// requestRecord is the audit record of a request served by Kayra: the
// api, namespace, resource and verb read from its path as /check reads an
// app's, and its outcome.
func requestRecord(c *gin.Context) audit.Record {
	status := c.Writer.Status()
	r := audit.Record{
		Stage: audit.StageRequest, RequestID: c.GetHeader(libserver.RequestIDHeader), SourceIP: c.ClientIP(),
		UserAgent: c.Request.UserAgent(), Status: status,
		Allowed: status != http.StatusUnauthorized && status != http.StatusForbidden,
	}
	if ac, ok := middleware.GetAuth(c); ok {
		r.User, r.Groups, r.Kind, r.ClientID = ac.UserID, ac.Groups, ac.Kind, ac.ClientID
	}
	if !r.Allowed {
		// a gin middleware's refusal, or a generated handler's (server.AbortError)
		var e *liberrors.Error
		if err, ok := httpapi.Failure(c); ok {
			r.Reason = err.Message
		} else if liberrors.As(libserver.ErrorOf(c), &e) {
			r.Reason = e.Message
		}
	}
	rest := strings.Trim(strings.TrimPrefix(c.Request.URL.Path, "/oauth2/"), "/")
	r.API = "oauth2"
	if p, err := libapi.Parse(c.Request.URL.Path); err == nil {
		r.API, r.Namespace, rest = p.API, p.Namespace, p.Resource
	}
	resource, hasID, err := libauth.ParseResource(rest)
	if err != nil {
		resource = rest
	}
	r.Resource = resource
	r.Verb, _ = libauth.VerbFor(c.Request.Method, hasID)
	if segs := strings.Split(rest, "/"); len(segs) >= 2 {
		if len(segs)%2 == 0 {
			r.Name = segs[len(segs)-1]
		} else {
			r.Name = segs[len(segs)-2]
		}
	}
	return r
}

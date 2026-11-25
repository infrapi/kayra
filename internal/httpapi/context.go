package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Request is what a handler of the generated Handlers, which gets the
// request's context only, may still need of the request: its path and
// method (decided on as /check decides them), its route's parameters,
// where it came from (the audit's), and the response's header.
type Request struct {
	Method, Path        string
	Params              gin.Params
	ClientIP, UserAgent string
	// Header is the response's: set before the handler returns, a
	// Retry-After say.
	Header http.Header
}

type requestKey struct{}

// WithRequest puts c's Request in its request's context, for the
// handlers behind it: a middleware in front of the generated Register.
func WithRequest(c *gin.Context) {
	r := &Request{
		Method: c.Request.Method, Path: c.Request.URL.Path, Params: c.Params,
		ClientIP: c.ClientIP(), UserAgent: c.Request.UserAgent(), Header: c.Writer.Header(),
	}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestKey{}, r))
	c.Next()
}

// RequestOf is ctx's Request; an empty one outside a request (a test
// calling a handler directly).
func RequestOf(ctx context.Context) *Request {
	if r, ok := ctx.Value(requestKey{}).(*Request); ok {
		return r
	}
	return &Request{Header: http.Header{}}
}

// Err is e as an error: nil when e is, never a nil *liberrors.Error in a
// non-nil error.
func Err(e *liberrors.Error) error {
	if e == nil {
		return nil
	}
	return e
}

// Convert is v as a T, through JSON: a stored object as its API type, or
// the other way. Both are written the same, field by field.
func Convert[T any](v any) (T, error) {
	var out T
	data, err := json.Marshal(v)
	if err != nil {
		return out, err
	}
	return out, json.Unmarshal(data, &out)
}

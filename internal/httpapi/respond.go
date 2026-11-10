// Package httpapi centralises how every Kayra handler turns an error into
// an HTTP response, using infrapi/lib's RFC 9457 problem-detail payload.
package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Fail writes err as the response body and aborts the gin context, so no
// further handler in the chain runs (middleware refusing a request included).
func Fail(c *gin.Context, err *liberrors.Error) {
	c.Data(err.Code, liberrors.MediaType, mustJSON(err))
	c.Abort()
}

// Write is Fail for a plain net/http handler (no gin context) — e.g.
// kayra-cli's own loopback login listener, whose error responses a user
// sees in their browser just like any API error.
func Write(w http.ResponseWriter, err *liberrors.Error) {
	w.Header().Set("Content-Type", liberrors.MediaType)
	w.WriteHeader(err.Code)
	_, _ = w.Write(mustJSON(err))
}

func mustJSON(err *liberrors.Error) []byte {
	data, marshalErr := err.MarshalJSON()
	if marshalErr != nil {
		// MarshalJSON on *Error never fails in practice (plain struct,
		// no cyclic or unsupported fields); fall back to the detail text.
		return []byte(`{"detail":"` + err.Message + `"}`)
	}
	return data
}

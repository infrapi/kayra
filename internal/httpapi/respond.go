// Package httpapi centralises how every Kayra handler turns an error into
// an HTTP response, using infrapi/lib's RFC 9457 problem-detail payload.
package httpapi

import (
	"github.com/gin-gonic/gin"

	liberrors "github.com/infrapi/lib/pkg/errors"
)

// Fail writes err as the response body and aborts the gin context, so no
// further handler in the chain runs (middleware refusing a request included).
func Fail(c *gin.Context, err *liberrors.Error) {
	c.Data(err.Code, liberrors.MediaType, mustJSON(err))
	c.Abort()
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

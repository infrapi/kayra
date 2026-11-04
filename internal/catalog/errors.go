package catalog

import (
	"net/http"

	"github.com/infrapi/kayra/internal/store"
	liberrors "github.com/infrapi/lib/pkg/errors"
)

// notFoundOrInternal turns a Repository Get error into a 404 when it is
// store.ErrNotFound, or a 500 for anything else (a corrupt record, a
// backend outage), always carrying origin/format/args as the detail.
// Deliberately duplicated from internal/rbac's identical helper rather
// than shared: it's eight lines with no state, and importing rbac just
// for this would be a worse trade than the duplication.
func notFoundOrInternal(err error, origin, format string, args ...any) *liberrors.Error {
	if err == store.ErrNotFound {
		return liberrors.New(http.StatusNotFound, origin, format, args...)
	}
	return liberrors.Wrap(err, http.StatusInternalServerError, origin, format, args...)
}

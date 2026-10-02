package api

import (
	"net/http"

	"github.com/prampec/trustmate/internal/store"
)

// handleCAPem serves the latest certificate of the given kind
// (root/intermediate) as raw PEM -- the AIA caIssuers download target.
func handleCAPem(deps Deps, kind store.CertKind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		recs, err := deps.Store.Certificates().FindByKind(r.Context(), kind)
		if err != nil {
			deps.Logger.Error("finding CA certificate failed", "kind", kind, "err", err)
			writeInternalError(w)
			return
		}
		if len(recs) == 0 {
			writeProblem(w, probNotFound, "CA certificate "+string(kind)+" has not been bootstrapped", nil)
			return
		}
		rec := recs[len(recs)-1]
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(rec.PEM)
	}
}

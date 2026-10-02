package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec documents every route NewRouter can register, including
// those of disabled modules -- TestOpenAPISpecMatchesRouter keeps the
// two in sync.
//
//go:embed openapi.yaml
var openAPISpec []byte

func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}

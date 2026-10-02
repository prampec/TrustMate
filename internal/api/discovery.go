package api

import (
	"bytes"
	_ "embed"
	"net/http"
	"strings"
	"text/template"
)

// openAPISpec documents every route NewRouter can register, including
// those of disabled modules -- TestOpenAPISpecMatchesRouter keeps the
// two in sync.
//
//go:embed openapi.yaml
var openAPISpec []byte

//go:embed llms.txt.tmpl
var llmsTxtTemplate string

var llmsTxt = template.Must(template.New("llms.txt").Parse(llmsTxtTemplate))

func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}

// handleLLMsTxt renders the llms.txt once at router construction: its
// inputs are all fixed for the process lifetime. It deliberately lists
// only what an unauthenticated caller could already learn by probing --
// enabled modules and public URLs -- never profiles, clients or the
// server version.
func handleLLMsTxt(deps Deps) http.HandlerFunc {
	var buf bytes.Buffer
	instance := deps.InstanceName
	if instance == "" {
		instance = "TrustMate"
	}
	if err := llmsTxt.Execute(&buf, map[string]any{
		"InstanceName": instance,
		"BaseURL":      strings.TrimRight(deps.PublicBaseURL, "/"),
		"Revocation":   deps.ModuleConfig.EnableRevocation,
		"TSA":          deps.ModuleConfig.EnableTSA,
		"ACME":         deps.ModuleConfig.EnableACME,
	}); err != nil {
		panic("api: rendering llms.txt: " + err.Error())
	}
	body := buf.Bytes()
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}

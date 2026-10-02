package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type routeInfo struct {
	role string // "", "manager" or "admin"
}

// registeredRoutes reads router.go's source rather than probing the mux,
// because http.ServeMux can't enumerate its patterns and probing can't
// tell which role a route requires.
func registeredRoutes(t *testing.T) map[string]routeInfo {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing router.go: %v", err)
	}
	routes := map[string]routeInfo{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquoting %s: %v", lit.Value, err)
		}
		info := routeInfo{}
		if inner, ok := call.Args[1].(*ast.CallExpr); ok {
			if id, ok := inner.Fun.(*ast.Ident); ok && id.Name == "requireRole" && len(inner.Args) == 3 {
				if roleSel, ok := inner.Args[1].(*ast.SelectorExpr); ok {
					info.role = strings.ToLower(strings.TrimPrefix(roleSel.Sel.Name, "Role"))
				}
			}
		}
		routes[pattern] = info
		return true
	})
	if len(routes) == 0 {
		t.Fatal("found no routes in router.go")
	}
	return routes
}

type specOperation struct {
	RequiredRole string           `yaml:"x-required-role"`
	Security     []map[string]any `yaml:"security"`
}

func specRoutes(t *testing.T) map[string]specOperation {
	t.Helper()
	var doc struct {
		OpenAPI string                              `yaml:"openapi"`
		Paths   map[string]map[string]specOperation `yaml:"paths"`
	}
	if err := yaml.Unmarshal(openAPISpec, &doc); err != nil {
		t.Fatalf("parsing openapi.yaml: %v", err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		t.Fatalf("openapi version = %q, want 3.x", doc.OpenAPI)
	}
	ops := map[string]specOperation{}
	for path, methods := range doc.Paths {
		for method, op := range methods {
			ops[strings.ToUpper(method)+" "+path] = op
		}
	}
	return ops
}

// The spec names the CRL path segment {file} with an enum of
// root.crl/intermediate.crl, while the router registers {ca} and strips
// the suffix itself (see handleCRL).
var specPathAliases = map[string]string{
	"GET /v1/crl/{file}": "GET /v1/crl/{ca}",
}

func TestOpenAPISpecMatchesRouter(t *testing.T) {
	routes := registeredRoutes(t)
	spec := specRoutes(t)

	normalized := map[string]specOperation{}
	for k, op := range spec {
		if alias, ok := specPathAliases[k]; ok {
			k = alias
		}
		normalized[k] = op
	}

	var missing, extra []string
	for pattern := range routes {
		if _, ok := normalized[pattern]; !ok {
			missing = append(missing, pattern)
		}
	}
	for k := range normalized {
		if _, ok := routes[k]; !ok {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, m := range missing {
		t.Errorf("route %q is registered but not documented in openapi.yaml", m)
	}
	for _, e := range extra {
		t.Errorf("openapi.yaml documents %q but router.go does not register it", e)
	}

	for pattern, info := range routes {
		op, ok := normalized[pattern]
		if !ok {
			continue
		}
		if op.RequiredRole != info.role {
			t.Errorf("%s: x-required-role = %q, router requires %q", pattern, op.RequiredRole, info.role)
		}
		if (info.role != "") != (len(op.Security) > 0) {
			t.Errorf("%s: spec security = %v, router role = %q", pattern, op.Security, info.role)
		}
	}
}

func TestOpenAPIRouteServesSpec(t *testing.T) {
	router := NewRouter(Deps{Logger: testLogger(), ModuleConfig: ModuleConfig{EnableDiscovery: true}}, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/openapi.yaml", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/yaml" {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}
	if rec.Body.String() != string(openAPISpec) {
		t.Error("body does not match embedded spec")
	}
}

func TestOpenAPIRouteAbsentWhenDiscoveryDisabled(t *testing.T) {
	router := NewRouter(Deps{Logger: testLogger()}, nil)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/openapi.yaml", nil))

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

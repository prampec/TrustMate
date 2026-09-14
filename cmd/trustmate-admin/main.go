// Command trustmate-admin is the operator CLI for TrustMate's admin-only
// REST endpoints: certificate profiles, the API client roster, and the
// audit trail. It is a thin wrapper over the same REST API a human would
// otherwise need a GUI for -- see docs/design.md's Phase 3 roadmap entry
// and internal/cliclient, which both this and cmd/trustmate-management
// share.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/prampec/trustmate/internal/cliclient"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "profiles":
		runProfiles(os.Args[2:])
	case "clients":
		runClients(os.Args[2:])
	case "audit":
		runAudit(os.Args[2:])
	case "acme":
		runACME(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `trustmate-admin: operator CLI for TrustMate's admin-only REST endpoints.

Usage:
  trustmate-admin profiles list    [flags]
  trustmate-admin profiles reload  [flags]
  trustmate-admin clients add      --csr=<file> --role=admin|manager [flags]
  trustmate-admin clients list     [flags]
  trustmate-admin audit list       [--limit=N] [flags]
  trustmate-admin acme issue-eab-token --role=admin|manager [flags]

Flags (all connection flags default from TRUSTMATE_CLIENT_{SERVER,CERT,KEY,CA}):
  --server   TrustMate server base URL (default https://localhost:8080)
  --cert     client certificate PEM (must hold the admin role)
  --key      client private key PEM
  --ca       CA bundle PEM to verify the server
`)
}

func runProfiles(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("profiles "+args[0], flag.ExitOnError)
	connFlags := cliclient.RegisterFlags(fs)
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	client := mustClient(connFlags)

	switch args[0] {
	case "list":
		var out any
		if err := client.Get("/v1/profiles", &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	case "reload":
		var out any
		if err := client.Post("/v1/profiles/reload", nil, &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	default:
		usage()
		os.Exit(2)
	}
}

func runClients(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("clients "+sub, flag.ExitOnError)
	connFlags := cliclient.RegisterFlags(fs)
	csrPath := fs.String("csr", "", "path to a PEM-encoded CSR (clients add)")
	role := fs.String("role", "", "role to assign: admin or manager (clients add)")
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	client := mustClient(connFlags)

	switch sub {
	case "add":
		if *csrPath == "" || *role == "" {
			fatal(fmt.Errorf("--csr and --role are required"))
		}
		csrPEM, err := os.ReadFile(*csrPath)
		if err != nil {
			fatal(err)
		}
		var out any
		body := map[string]string{"csr": string(csrPEM), "role": *role}
		if err := client.Post("/v1/clients", body, &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	case "list":
		var out any
		if err := client.Get("/v1/clients", &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	default:
		usage()
		os.Exit(2)
	}
}

func runAudit(args []string) {
	if len(args) < 1 || args[0] != "list" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("audit list", flag.ExitOnError)
	connFlags := cliclient.RegisterFlags(fs)
	limit := fs.Int("limit", 0, "max entries to return")
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	client := mustClient(connFlags)

	path := "/v1/audit"
	if *limit > 0 {
		path = fmt.Sprintf("%s?limit=%d", path, *limit)
	}
	var out any
	if err := client.Get(path, &out); err != nil {
		fatal(err)
	}
	printJSON(out)
}

// runACME issues an External Account Binding token -- the credential
// that starts RFC 8555 automated enrollment (see internal/api/acme.go
// and docs/design.md's Phase 5 roadmap entry). The printed hmac_key is
// shown once; the server never returns it again.
func runACME(args []string) {
	if len(args) < 1 || args[0] != "issue-eab-token" {
		usage()
		os.Exit(2)
	}
	fs := flag.NewFlagSet("acme issue-eab-token", flag.ExitOnError)
	connFlags := cliclient.RegisterFlags(fs)
	role := fs.String("role", "manager", "role to bind issued certificates to: admin or manager")
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	client := mustClient(connFlags)

	var out any
	body := map[string]string{"role": *role}
	if err := client.Post("/v1/acme/eab-tokens", body, &out); err != nil {
		fatal(err)
	}
	printJSON(out)
}

func mustClient(f *cliclient.Flags) *cliclient.Client {
	client, err := cliclient.New(f)
	if err != nil {
		fatal(err)
	}
	return client
}

func printJSON(v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(data))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "trustmate-admin:", err)
	os.Exit(1)
}

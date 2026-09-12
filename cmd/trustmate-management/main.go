// Command trustmate-management is the operator CLI for TrustMate's
// certificate-lifecycle REST endpoints: issue, look up, and revoke.
// A thin wrapper over the REST API, sharing internal/cliclient with
// cmd/trustmate-admin -- see docs/design.md's Phase 3 roadmap entry.
//
// Key rotation is explicitly out of scope for this phase: rotating live
// CA/TSA key material safely (re-chaining existing leaves, keystore
// migration) is deferred to a later phase.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/prampec/trustmate/internal/cliclient"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "certificates" {
		usage()
		os.Exit(2)
	}
	runCertificates(os.Args[2:])
}

func usage() {
	fmt.Fprint(os.Stderr, `trustmate-management: operator CLI for TrustMate certificate operations.

Usage:
  trustmate-management certificates issue   --profile=<name> --csr=<file> [flags]
  trustmate-management certificates get     [flags] <serial>
  trustmate-management certificates revoke  [--reason=<reason>] [flags] <serial>

Flags must come before the positional <serial> argument (Go's flag
package stops parsing at the first non-flag argument).

Flags (all connection flags default from TRUSTMATE_CLIENT_{SERVER,CERT,KEY,CA}):
  --server   TrustMate server base URL (default https://localhost:8080)
  --cert     client certificate PEM (must hold the manager or admin role)
  --key      client private key PEM
  --ca       CA bundle PEM to verify the server
`)
}

func runCertificates(args []string) {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("certificates "+sub, flag.ExitOnError)
	connFlags := cliclient.RegisterFlags(fs)
	profile := fs.String("profile", "", "profile to issue against (issue)")
	csrPath := fs.String("csr", "", "path to a PEM-encoded CSR (issue)")
	reason := fs.String("reason", "", "revocation reason (revoke)")
	if err := fs.Parse(args[1:]); err != nil {
		fatal(err)
	}
	client := mustClient(connFlags)
	rest := fs.Args()

	switch sub {
	case "issue":
		if *profile == "" || *csrPath == "" {
			fatal(fmt.Errorf("--profile and --csr are required"))
		}
		csrPEM, err := os.ReadFile(*csrPath)
		if err != nil {
			fatal(err)
		}
		var out any
		body := map[string]string{"profile": *profile, "csr": string(csrPEM)}
		if err := client.Post("/v1/certificates", body, &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	case "get":
		if len(rest) != 1 {
			fatal(fmt.Errorf("expected exactly one serial argument"))
		}
		var out any
		if err := client.Get("/v1/certificates/"+rest[0], &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	case "revoke":
		if len(rest) != 1 {
			fatal(fmt.Errorf("expected exactly one serial argument"))
		}
		var body any
		if *reason != "" {
			body = map[string]string{"reason": *reason}
		}
		var out any
		if err := client.Post("/v1/certificates/"+rest[0]+"/revoke", body, &out); err != nil {
			fatal(err)
		}
		printJSON(out)
	default:
		usage()
		os.Exit(2)
	}
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
	fmt.Fprintln(os.Stderr, "trustmate-management:", err)
	os.Exit(1)
}

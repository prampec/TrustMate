// Command trustmate-mcp is a local Model Context Protocol server that
// exposes TrustMate's REST API as MCP tools over stdio. It is a thin
// wrapper over internal/cliclient, like cmd/trustmate-admin and
// cmd/trustmate-management: the MCP client (an AI assistant) never sees
// the mTLS client certificate, it only gets whatever that certificate's
// role allows.
//
// Private keys for newly issued certificates are generated locally and
// written to --output-dir; they never travel through the MCP channel.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prampec/trustmate/internal/cliclient"
	"github.com/prampec/trustmate/internal/version"
)

func main() {
	fs := flag.NewFlagSet("trustmate-mcp", flag.ExitOnError)
	fs.Usage = usage
	connFlags := cliclient.RegisterFlags(fs)
	outputDir := fs.String("output-dir", envOr("TRUSTMATE_MCP_OUTPUT_DIR", "."), "directory where generated keys, certificates and timestamp tokens are written")
	readOnly := fs.Bool("read-only", envOr("TRUSTMATE_MCP_READ_ONLY", "") == "true", "expose only tools that neither change server state nor write local files")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if *showVersion {
		fmt.Println("trustmate-mcp " + version.Version)
		return
	}

	client, err := cliclient.New(connFlags)
	if err != nil {
		fatal(err)
	}
	dir, err := filepath.Abs(*outputDir)
	if err != nil {
		fatal(err)
	}

	server := newServer(&toolset{client: client, outputDir: dir}, *readOnly)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// stdout is the MCP channel, so diagnostics must go to stderr only.
	log.SetOutput(os.Stderr)
	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && ctx.Err() == nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `trustmate-mcp: MCP (stdio) server exposing the TrustMate REST API as tools.

Usage:
  trustmate-mcp [flags]

Intended to be launched by an MCP client (Claude Code, Claude Desktop,
...), not run interactively. The tools available to the assistant are
bounded by the role of the client certificate configured here -- use a
manager-role certificate unless admin tools are really needed.

Flags (connection flags default from TRUSTMATE_CLIENT_{SERVER,CERT,KEY,CA}):
  --server      TrustMate server base URL (default https://localhost:8080)
  --cert        client certificate PEM (mTLS identity)
  --key         client private key PEM
  --ca          CA bundle PEM to verify the server
  --output-dir  where generated keys/certificates/timestamp tokens are
                written (default ".", or TRUSTMATE_MCP_OUTPUT_DIR)
  --read-only   only register tools that neither change server state nor
                write local files (or TRUSTMATE_MCP_READ_ONLY=true)
  --version     print version and exit
`)
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "trustmate-mcp:", err)
	os.Exit(1)
}

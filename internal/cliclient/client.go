// Package cliclient is the mTLS REST client shared by cmd/trustmate-admin
// and cmd/trustmate-management -- both CLIs are thin wrappers over the
// same admin/manager REST endpoints a human would otherwise need a GUI
// for, so the HTTP/TLS plumbing lives here once instead of twice. See
// docs/design.md's Phase 3 roadmap entry ("admin and management CLI").
package cliclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Flags holds the connection flags both CLIs register identically.
type Flags struct {
	Server string
	Cert   string
	Key    string
	CA     string
}

// RegisterFlags adds the shared connection flags to fs, defaulting from
// TRUSTMATE_CLIENT_{SERVER,CERT,KEY,CA} so a CLI invocation doesn't need
// to repeat them on every call.
func RegisterFlags(fs *flag.FlagSet) *Flags {
	f := &Flags{}
	fs.StringVar(&f.Server, "server", envOr("TRUSTMATE_CLIENT_SERVER", "https://localhost:8080"), "TrustMate server base URL")
	fs.StringVar(&f.Cert, "cert", envOr("TRUSTMATE_CLIENT_CERT", ""), "path to the client certificate PEM (mTLS identity)")
	fs.StringVar(&f.Key, "key", envOr("TRUSTMATE_CLIENT_KEY", ""), "path to the client private key PEM")
	fs.StringVar(&f.CA, "ca", envOr("TRUSTMATE_CLIENT_CA", ""), "path to a CA bundle PEM to verify the server (defaults to the system trust store)")
	return f
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

// Client is a small JSON-over-mTLS REST client.
type Client struct {
	http    *http.Client
	baseURL string
}

// New builds a Client from f. --cert and --key are required: every route
// these CLIs call is behind requireRole, which needs a client certificate
// to look up a role for.
func New(f *Flags) (*Client, error) {
	if f.Cert == "" || f.Key == "" {
		return nil, fmt.Errorf("cliclient: --cert and --key (or TRUSTMATE_CLIENT_CERT/TRUSTMATE_CLIENT_KEY) are required")
	}
	cert, err := tls.LoadX509KeyPair(f.Cert, f.Key)
	if err != nil {
		return nil, fmt.Errorf("cliclient: loading client certificate/key: %w", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if f.CA != "" {
		caPEM, err := os.ReadFile(f.CA)
		if err != nil {
			return nil, fmt.Errorf("cliclient: reading CA bundle %s: %w", f.CA, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("cliclient: no certificates found in CA bundle %s", f.CA)
		}
		tlsConfig.RootCAs = pool
	}
	return &Client{
		http:    &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}},
		baseURL: strings.TrimRight(f.Server, "/"),
	}, nil
}

// Get issues a GET request and decodes a JSON response into out (which
// may be nil to discard the body).
func (c *Client) Get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

// Post issues a POST request with body JSON-encoded (body may be nil for
// an empty request), decoding the JSON response into out (which may be
// nil to discard the body).
func (c *Client) Post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

func (c *Client) do(method, path string, body, out any) error {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cliclient: encoding request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("cliclient: building request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cliclient: request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cliclient: reading response body: %w", err)
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cliclient: server returned %s: %s", resp.Status, string(data))
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("cliclient: decoding response body: %w", err)
	}
	return nil
}

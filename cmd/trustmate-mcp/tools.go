package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/prampec/trustmate/internal/cliclient"
	"github.com/prampec/trustmate/internal/version"
)

type toolset struct {
	client    *cliclient.Client
	outputDir string
}

func newServer(t *toolset, readOnly bool) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "trustmate", Version: version.Version}, &mcp.ServerOptions{
		Instructions: "Tools for operating a TrustMate certificate authority (certificate issuance, revocation, CRL, RFC 3161 timestamps). " +
			"Certificate serials are decimal strings. Private keys for newly issued certificates are generated locally and only their file path is returned. " +
			"Call preview_certificate before issue_certificate, and confirm with the user before any destructive tool. " +
			"Admin-only tools fail with 403 when the configured client certificate has the manager role. " +
			"Errors carry the server's RFC 9457 problem document; its extension members (e.g. available_profiles, allowed_values) say how to fix the request.",
	})

	readOnlyTool := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptr(false)}
	additive := &mcp.ToolAnnotations{DestructiveHint: ptr(false), OpenWorldHint: ptr(false)}
	destructive := &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(false)}

	t.addResources(s)
	addPrompts(s, readOnly)

	mcp.AddTool(s, &mcp.Tool{Name: "get_health", Annotations: readOnlyTool,
		Description: "Check TrustMate liveness and readiness; returns instance name and server version."}, t.getHealth)
	mcp.AddTool(s, &mcp.Tool{Name: "list_profiles", Annotations: readOnlyTool,
		Description: "List certificate profiles (name, key usages, validity, OCSP/CRL settings). Use a profile name with issue_certificate."}, t.listProfiles)
	mcp.AddTool(s, &mcp.Tool{Name: "get_certificate", Annotations: readOnlyTool,
		Description: "Look up a certificate by decimal serial: subject, profile, validity, revocation status and PEM."}, t.getCertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "get_ca_certificate", Annotations: readOnlyTool,
		Description: "Fetch the root or intermediate CA certificate (PEM plus decoded subject/validity)."}, t.getCACertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "get_crl", Annotations: readOnlyTool,
		Description: "Fetch and decode the current CRL published by the root or intermediate CA: update times and revoked serials. Requires the revocation module."}, t.getCRL)
	mcp.AddTool(s, &mcp.Tool{Name: "preview_certificate", Annotations: readOnlyTool,
		Description: "Dry run of issue_certificate: shows the subject, validity, key usages and AIA/OCSP/CRL URLs the profile would produce, without signing, " +
			"storing or writing anything. Takes the same subject inputs as issue_certificate (common_name/dns_names/key_type, or csr_pem); a generated key is discarded."}, t.previewCertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "list_clients", Annotations: readOnlyTool,
		Description: "List API client certificates and their roles (admin role required)."}, t.listClients)
	mcp.AddTool(s, &mcp.Tool{Name: "list_audit", Annotations: readOnlyTool,
		Description: "List audit trail entries, newest first (admin role required)."}, t.listAudit)

	if readOnly {
		return s
	}

	mcp.AddTool(s, &mcp.Tool{Name: "issue_certificate", Annotations: additive,
		Description: "Issue a leaf certificate against a profile. By default a new key pair is generated locally and written to <name>.key.pem (mode 0600) " +
			"in the output directory, with the certificate in <name>.cert.pem; the key itself is never returned. " +
			"Alternatively pass csr_pem to have an existing CSR signed (then common_name/dns_names/key_type must be empty)."}, t.issueCertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "revoke_certificate", Annotations: destructive,
		Description: "Permanently revoke a certificate by decimal serial. Cannot be undone. Confirm with the user before calling."}, t.revokeCertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "issue_client_certificate", Annotations: destructive,
		Description: "Issue an API client certificate with the admin or manager role, granting access to this TrustMate instance (admin role required). " +
			"Key and certificate are written locally like issue_certificate. Confirm with the user before calling."}, t.issueClientCertificate)
	mcp.AddTool(s, &mcp.Tool{Name: "reload_profiles", Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(false), IdempotentHint: true, OpenWorldHint: ptr(false)},
		Description: "Reload certificate profiles from the server's profile directory (admin role required)."}, t.reloadProfiles)
	mcp.AddTool(s, &mcp.Tool{Name: "rotate_tsa", Annotations: destructive,
		Description: "Mint a new TSA signing identity and switch the server to it for new timestamps; the previous identity stays valid (admin role required). Confirm with the user before calling."}, t.rotateTSA)
	mcp.AddTool(s, &mcp.Tool{Name: "timestamp_file", Annotations: additive,
		Description: "Obtain an RFC 3161 timestamp for a local file. Only its SHA-256 digest is sent to the server; the response token is written to <name>.tsr in the output directory. Requires the TSA module."}, t.timestampFile)

	return s
}

func ptr[T any](v T) *T { return &v }

// Serials go straight into the URL path, so anything but decimal digits
// is rejected rather than escaped -- there is no legitimate other form.
var serialPattern = regexp.MustCompile(`^[0-9]{1,80}$`)

func checkSerial(serial string) error {
	if !serialPattern.MatchString(serial) {
		return fmt.Errorf("serial %q must be a decimal number", serial)
	}
	return nil
}

type empty struct{}

type healthOutput struct {
	Health    map[string]any `json:"health"`
	Readiness map[string]any `json:"readiness"`
}

func (t *toolset) getHealth(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, healthOutput, error) {
	var out healthOutput
	if err := t.client.Get("/healthz", &out.Health); err != nil {
		return nil, out, err
	}
	if err := t.client.Get("/readyz", &out.Readiness); err != nil {
		out.Readiness = map[string]any{"status": "not ready", "error": err.Error()}
	}
	return nil, out, nil
}

type profilesOutput struct {
	Profiles []map[string]any `json:"profiles"`
}

func (t *toolset) listProfiles(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, profilesOutput, error) {
	var out profilesOutput
	err := t.client.Get("/v1/profiles", &out.Profiles)
	return nil, out, err
}

type serialInput struct {
	Serial string `json:"serial" jsonschema:"certificate serial number, decimal"`
}

func (t *toolset) getCertificate(ctx context.Context, _ *mcp.CallToolRequest, in serialInput) (*mcp.CallToolResult, map[string]any, error) {
	if err := checkSerial(in.Serial); err != nil {
		return nil, nil, err
	}
	var out map[string]any
	err := t.client.Get("/v1/certificates/"+in.Serial, &out)
	return nil, out, err
}

type caInput struct {
	CA string `json:"ca" jsonschema:"which CA: root or intermediate"`
}

func checkCA(ca string) error {
	if ca != "root" && ca != "intermediate" {
		return fmt.Errorf("ca must be \"root\" or \"intermediate\", got %q", ca)
	}
	return nil
}

type caCertificateOutput struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	PEM       string    `json:"pem"`
}

func (t *toolset) getCACertificate(ctx context.Context, _ *mcp.CallToolRequest, in caInput) (*mcp.CallToolResult, caCertificateOutput, error) {
	var out caCertificateOutput
	if err := checkCA(in.CA); err != nil {
		return nil, out, err
	}
	data, err := t.client.GetRaw("/v1/ca/" + in.CA + ".pem")
	if err != nil {
		return nil, out, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, out, fmt.Errorf("server returned no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, out, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return nil, caCertificateOutput{
		Subject:   cert.Subject.String(),
		Issuer:    cert.Issuer.String(),
		Serial:    cert.SerialNumber.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		PEM:       string(data),
	}, nil
}

type revokedEntry struct {
	Serial    string    `json:"serial"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    int       `json:"reason_code" jsonschema:"RFC 5280 CRLReason code"`
}

type crlOutput struct {
	Issuer     string         `json:"issuer"`
	Number     string         `json:"number,omitempty"`
	ThisUpdate time.Time      `json:"this_update"`
	NextUpdate time.Time      `json:"next_update"`
	Revoked    []revokedEntry `json:"revoked"`
}

func (t *toolset) getCRL(ctx context.Context, _ *mcp.CallToolRequest, in caInput) (*mcp.CallToolResult, crlOutput, error) {
	var out crlOutput
	if err := checkCA(in.CA); err != nil {
		return nil, out, err
	}
	der, err := t.client.GetRaw("/v1/crl/" + in.CA + ".crl")
	if err != nil {
		return nil, out, err
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, out, fmt.Errorf("parsing CRL: %w", err)
	}
	out = crlOutput{
		Issuer:     crl.Issuer.String(),
		ThisUpdate: crl.ThisUpdate,
		NextUpdate: crl.NextUpdate,
		Revoked:    []revokedEntry{},
	}
	if crl.Number != nil {
		out.Number = crl.Number.String()
	}
	for _, e := range crl.RevokedCertificateEntries {
		out.Revoked = append(out.Revoked, revokedEntry{Serial: e.SerialNumber.String(), RevokedAt: e.RevocationTime, Reason: e.ReasonCode})
	}
	return nil, out, nil
}

type clientsOutput struct {
	Clients []map[string]any `json:"clients"`
}

func (t *toolset) listClients(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, clientsOutput, error) {
	var out clientsOutput
	err := t.client.Get("/v1/clients", &out.Clients)
	return nil, out, err
}

type auditInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of entries to return; omit for the server default"`
}

type auditOutput struct {
	Entries []map[string]any `json:"entries"`
}

func (t *toolset) listAudit(ctx context.Context, _ *mcp.CallToolRequest, in auditInput) (*mcp.CallToolResult, auditOutput, error) {
	var out auditOutput
	path := "/v1/audit"
	if in.Limit > 0 {
		path += "?" + url.Values{"limit": {strconv.Itoa(in.Limit)}}.Encode()
	}
	err := t.client.Get(path, &out.Entries)
	return nil, out, err
}

type issueCertificateInput struct {
	Profile    string   `json:"profile" jsonschema:"certificate profile name (see list_profiles)"`
	Name       string   `json:"name" jsonschema:"base file name for the outputs, e.g. 'web01' writes web01.key.pem and web01.cert.pem"`
	CommonName string   `json:"common_name,omitempty" jsonschema:"subject common name for the generated key's CSR"`
	DNSNames   []string `json:"dns_names,omitempty" jsonschema:"DNS subject alternative names for the generated key's CSR"`
	KeyType    string   `json:"key_type,omitempty" jsonschema:"ecdsa-p256 (default), ecdsa-p384, rsa-3072 or rsa-4096"`
	CSRPEM     string   `json:"csr_pem,omitempty" jsonschema:"existing PEM CSR to sign instead of generating a key locally"`
}

type issuedOutput struct {
	Serial    string    `json:"serial"`
	Subject   string    `json:"subject"`
	Profile   string    `json:"profile,omitempty"`
	Role      string    `json:"role,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	CertPath  string    `json:"cert_path"`
	KeyPath   string    `json:"key_path,omitempty"`
}

func (t *toolset) issueCertificate(ctx context.Context, _ *mcp.CallToolRequest, in issueCertificateInput) (*mcp.CallToolResult, issuedOutput, error) {
	var out issuedOutput
	if in.Profile == "" {
		return nil, out, fmt.Errorf("profile is required")
	}
	generate := in.CSRPEM == ""
	var keyPEM, csrPEM []byte
	if !generate {
		if in.CommonName != "" || len(in.DNSNames) > 0 || in.KeyType != "" {
			return nil, out, fmt.Errorf("common_name, dns_names and key_type must be empty when csr_pem is given; the CSR defines them")
		}
		csrPEM = []byte(in.CSRPEM)
	} else if in.CommonName == "" && len(in.DNSNames) == 0 {
		return nil, out, fmt.Errorf("common_name or dns_names is required when generating a key")
	}
	if err := t.prepareOutputs(in.Name, generate); err != nil {
		return nil, out, err
	}
	if generate {
		var err error
		if keyPEM, csrPEM, err = generateKeyAndCSR(in.KeyType, in.CommonName, in.DNSNames); err != nil {
			return nil, out, err
		}
	}

	var resp struct {
		Serial    string    `json:"serial"`
		Profile   string    `json:"profile"`
		NotBefore time.Time `json:"not_before"`
		NotAfter  time.Time `json:"not_after"`
		PEM       string    `json:"pem"`
	}
	if err := t.client.Post("/v1/certificates", map[string]string{"profile": in.Profile, "csr": string(csrPEM)}, &resp); err != nil {
		return nil, out, err
	}
	out = issuedOutput{Serial: resp.Serial, Profile: resp.Profile, NotBefore: resp.NotBefore, NotAfter: resp.NotAfter}
	return nil, out, t.saveIssued(in.Name, keyPEM, resp.PEM, &out)
}

type previewCertificateInput struct {
	Profile    string   `json:"profile" jsonschema:"certificate profile name (see list_profiles)"`
	CommonName string   `json:"common_name,omitempty" jsonschema:"subject common name"`
	DNSNames   []string `json:"dns_names,omitempty" jsonschema:"DNS subject alternative names"`
	KeyType    string   `json:"key_type,omitempty" jsonschema:"ecdsa-p256 (default), ecdsa-p384, rsa-3072 or rsa-4096"`
	CSRPEM     string   `json:"csr_pem,omitempty" jsonschema:"existing PEM CSR to preview instead of a generated one"`
}

func (t *toolset) previewCertificate(ctx context.Context, _ *mcp.CallToolRequest, in previewCertificateInput) (*mcp.CallToolResult, map[string]any, error) {
	if in.Profile == "" {
		return nil, nil, fmt.Errorf("profile is required")
	}
	csrPEM := []byte(in.CSRPEM)
	if in.CSRPEM != "" {
		if in.CommonName != "" || len(in.DNSNames) > 0 || in.KeyType != "" {
			return nil, nil, fmt.Errorf("common_name, dns_names and key_type must be empty when csr_pem is given; the CSR defines them")
		}
	} else {
		if in.CommonName == "" && len(in.DNSNames) == 0 {
			return nil, nil, fmt.Errorf("common_name or dns_names is required when csr_pem is not given")
		}
		var err error
		// The server needs a CSR with a valid self-signature, so a key has
		// to exist; it stays in memory and is dropped on return.
		if _, csrPEM, err = generateKeyAndCSR(in.KeyType, in.CommonName, in.DNSNames); err != nil {
			return nil, nil, err
		}
	}
	var out map[string]any
	err := t.client.Post("/v1/certificates?dry_run=true", map[string]string{"profile": in.Profile, "csr": string(csrPEM)}, &out)
	return nil, out, err
}

type issueClientInput struct {
	Role       string `json:"role" jsonschema:"role to grant: admin or manager"`
	Name       string `json:"name" jsonschema:"base file name for the outputs, e.g. 'ci-bot' writes ci-bot.key.pem and ci-bot.cert.pem"`
	CommonName string `json:"common_name" jsonschema:"subject common name identifying the client"`
	KeyType    string `json:"key_type,omitempty" jsonschema:"ecdsa-p256 (default), ecdsa-p384, rsa-3072 or rsa-4096"`
}

func (t *toolset) issueClientCertificate(ctx context.Context, _ *mcp.CallToolRequest, in issueClientInput) (*mcp.CallToolResult, issuedOutput, error) {
	var out issuedOutput
	if in.Role != "admin" && in.Role != "manager" {
		return nil, out, fmt.Errorf("role must be \"admin\" or \"manager\"")
	}
	if in.CommonName == "" {
		return nil, out, fmt.Errorf("common_name is required")
	}
	if err := t.prepareOutputs(in.Name, true); err != nil {
		return nil, out, err
	}
	keyPEM, csrPEM, err := generateKeyAndCSR(in.KeyType, in.CommonName, nil)
	if err != nil {
		return nil, out, err
	}
	var resp struct {
		Serial string `json:"serial"`
		Role   string `json:"role"`
		PEM    string `json:"pem"`
	}
	if err := t.client.Post("/v1/clients", map[string]string{"csr": string(csrPEM), "role": in.Role}, &resp); err != nil {
		return nil, out, err
	}
	out = issuedOutput{Serial: resp.Serial, Role: resp.Role}
	return nil, out, t.saveIssued(in.Name, keyPEM, resp.PEM, &out)
}

func (t *toolset) prepareOutputs(name string, withKey bool) error {
	if err := validateName(name); err != nil {
		return err
	}
	names := []string{name + ".cert.pem"}
	if withKey {
		names = append(names, name+".key.pem")
	}
	return t.checkFree(names...)
}

// saveIssued writes the key (if one was generated) and certificate, and
// fills in the decoded subject/validity. The certificate already exists
// server-side at this point, so a write failure is reported together
// with its serial rather than silently losing track of it.
func (t *toolset) saveIssued(name string, keyPEM []byte, certPEM string, out *issuedOutput) error {
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			out.Subject = cert.Subject.String()
			out.NotBefore, out.NotAfter = cert.NotBefore, cert.NotAfter
		}
	}
	if keyPEM != nil {
		path, err := t.writeNew(name+".key.pem", keyPEM, 0o600)
		if err != nil {
			return fmt.Errorf("certificate %s was issued but writing its key failed (consider revoking it): %w", out.Serial, err)
		}
		out.KeyPath = path
	}
	path, err := t.writeNew(name+".cert.pem", []byte(certPEM), 0o644)
	if err != nil {
		return fmt.Errorf("certificate %s was issued but writing it failed (get_certificate can fetch it again): %w", out.Serial, err)
	}
	out.CertPath = path
	return nil
}

type revokeInput struct {
	Serial string `json:"serial" jsonschema:"certificate serial number, decimal"`
	Reason string `json:"reason,omitempty" jsonschema:"unspecified (default), keyCompromise, affiliationChanged, superseded or cessationOfOperation"`
}

func (t *toolset) revokeCertificate(ctx context.Context, _ *mcp.CallToolRequest, in revokeInput) (*mcp.CallToolResult, map[string]any, error) {
	if err := checkSerial(in.Serial); err != nil {
		return nil, nil, err
	}
	var body any
	if in.Reason != "" {
		body = map[string]string{"reason": in.Reason}
	}
	var out map[string]any
	err := t.client.Post("/v1/certificates/"+in.Serial+"/revoke", body, &out)
	return nil, out, err
}

func (t *toolset) reloadProfiles(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, map[string]any, error) {
	var out map[string]any
	err := t.client.Post("/v1/profiles/reload", nil, &out)
	return nil, out, err
}

type rotateTSAOutput struct {
	Serial         string    `json:"serial"`
	PreviousSerial string    `json:"previous_serial"`
	Profile        string    `json:"profile"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
}

func (t *toolset) rotateTSA(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, rotateTSAOutput, error) {
	var out rotateTSAOutput
	err := t.client.Post("/v1/tsa/rotate", nil, &out)
	return nil, out, err
}

type timestampInput struct {
	File string `json:"file" jsonschema:"absolute path of the local file to timestamp"`
	Name string `json:"name" jsonschema:"base file name for the token, e.g. 'contract' writes contract.tsr"`
}

type timestampOutput struct {
	TokenPath string    `json:"token_path"`
	SHA256    string    `json:"sha256"`
	Time      time.Time `json:"time"`
	Serial    string    `json:"serial"`
	Policy    string    `json:"policy"`
	TSA       string    `json:"tsa,omitempty"`
}

func (t *toolset) timestampFile(ctx context.Context, _ *mcp.CallToolRequest, in timestampInput) (*mcp.CallToolResult, timestampOutput, error) {
	var out timestampOutput
	if err := validateName(in.Name); err != nil {
		return nil, out, err
	}
	tokenName := in.Name + ".tsr"
	if err := t.checkFree(tokenName); err != nil {
		return nil, out, err
	}
	digest, err := sha256File(in.File)
	if err != nil {
		return nil, out, err
	}
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, out, err
	}
	query, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: digest, Certificates: true, Nonce: nonce}).Marshal()
	if err != nil {
		return nil, out, fmt.Errorf("building timestamp query: %w", err)
	}
	reply, err := t.client.PostRaw("/v1/tsa", "application/timestamp-query", query)
	if err != nil {
		return nil, out, err
	}
	ts, err := timestamp.ParseResponse(reply)
	if err != nil {
		return nil, out, fmt.Errorf("parsing timestamp reply: %w", err)
	}
	// A token for a different digest or nonce would be useless (or a
	// replay), so it is rejected before anything is written.
	if !bytes.Equal(ts.HashedMessage, digest) || ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, out, fmt.Errorf("timestamp reply does not match the request (digest or nonce mismatch)")
	}
	path, err := t.writeNew(tokenName, reply, 0o644)
	if err != nil {
		return nil, out, err
	}
	out = timestampOutput{
		TokenPath: path,
		SHA256:    hex.EncodeToString(digest),
		Time:      ts.Time,
		Serial:    ts.SerialNumber.String(),
		Policy:    ts.Policy.String(),
	}
	if len(ts.Certificates) > 0 {
		out.TSA = ts.Certificates[0].Subject.String()
	}
	return nil, out, nil
}

func sha256File(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

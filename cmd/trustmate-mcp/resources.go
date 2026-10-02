package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const certificateURIPrefix = "trustmate://certificates/"

// addResources exposes read-only server state as MCP resources, so a
// client can attach it as context without the model spending a tool call.
// Every read goes to the server; nothing is cached locally.
func (t *toolset) addResources(s *mcp.Server) {
	raw := func(uri, mimeType, path string) mcp.ResourceHandler {
		return func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			data, err := t.client.GetRaw(path)
			if err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: mimeType, Text: string(data)}}}, nil
		}
	}
	add := func(uri, name, mimeType, path, description string) {
		s.AddResource(&mcp.Resource{URI: uri, Name: name, MIMEType: mimeType, Description: description}, raw(uri, mimeType, path))
	}
	add("trustmate://ca/root.pem", "root-ca", "application/x-pem-file", "/v1/ca/root.pem",
		"Root CA certificate (PEM): the trust anchor for everything this CA issues.")
	add("trustmate://ca/intermediate.pem", "intermediate-ca", "application/x-pem-file", "/v1/ca/intermediate.pem",
		"Intermediate CA certificate (PEM): the direct issuer of all leaf certificates.")
	add("trustmate://profiles", "profiles", "application/json", "/v1/profiles",
		"Certificate profiles available for issuance (manager role).")
	add("trustmate://openapi.yaml", "openapi", "application/yaml", "/v1/openapi.yaml",
		"OpenAPI description of the TrustMate REST API, including required roles and the error catalogue. Absent when the server's discovery module is off.")

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: certificateURIPrefix + "{serial}",
		Name:        "certificate",
		MIMEType:    "application/json",
		Description: "A certificate record by decimal serial: subject, profile, validity, revocation status and PEM (manager role).",
	}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		uri := req.Params.URI
		serial := strings.TrimPrefix(uri, certificateURIPrefix)
		if err := checkSerial(serial); err != nil {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		data, err := t.client.GetRaw("/v1/certificates/" + serial)
		if err != nil {
			return nil, err
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(data)}}}, nil
	})
}

// addPrompts registers user-invocable workflows (slash commands in most
// MCP clients). They only steer the model through the existing tools, so
// the role and --read-only limits still apply; prompts that need a
// mutating tool are skipped in read-only mode.
func addPrompts(s *mcp.Server, readOnly bool) {
	s.AddPrompt(&mcp.Prompt{
		Name:        "certificate-status",
		Description: "Check whether a certificate is valid, expiring or revoked.",
		Arguments:   []*mcp.PromptArgument{{Name: "serial", Description: "decimal certificate serial", Required: true}},
	}, textPrompt(func(args map[string]string) (string, error) {
		serial := args["serial"]
		if err := checkSerial(serial); err != nil {
			return "", err
		}
		return fmt.Sprintf(`Report the status of TrustMate certificate %s.

1. Call get_certificate with serial %s.
2. Report its subject, profile, validity window and how many days remain, and whether it is revoked (with reason and time).
3. If the revocation module is enabled, call get_crl for the intermediate CA and confirm the CRL agrees. Mention that the CRL can lag up to its next-update time.`, serial, serial), nil
	}))

	if readOnly {
		return
	}

	s.AddPrompt(&mcp.Prompt{
		Name:        "issue-certificate",
		Description: "Issue a certificate: pick a profile, preview, confirm, then issue with a locally generated key.",
		Arguments: []*mcp.PromptArgument{
			{Name: "common_name", Description: "subject common name, e.g. a hostname", Required: true},
			{Name: "purpose", Description: "what the certificate is for, e.g. 'TLS server' or 'document signing'"},
		},
	}, textPrompt(func(args map[string]string) (string, error) {
		cn := strings.TrimSpace(args["common_name"])
		if cn == "" {
			return "", fmt.Errorf("common_name is required")
		}
		purpose := strings.TrimSpace(args["purpose"])
		if purpose == "" {
			purpose = "not stated; ask the user if the profile choice is ambiguous"
		}
		return fmt.Sprintf(`Issue a TrustMate certificate for common name %q. Purpose: %s.

1. Call list_profiles and pick the profile whose key usages fit the purpose. If none fits clearly, ask the user.
2. Call preview_certificate with that profile and common_name (add dns_names when the name is a hostname). Show the user the subject, validity, key usages and URLs.
3. Ask the user to confirm. Do not issue without confirmation.
4. Call issue_certificate with the same inputs and a short file name. Report the serial and the certificate and key file paths. Never print the private key.`, cn, purpose), nil
	}))

	s.AddPrompt(&mcp.Prompt{
		Name:        "revoke-certificate",
		Description: "Revoke a certificate safely: inspect, confirm, revoke, verify.",
		Arguments: []*mcp.PromptArgument{
			{Name: "serial", Description: "decimal certificate serial", Required: true},
			{Name: "reason", Description: "unspecified, keyCompromise, affiliationChanged, superseded or cessationOfOperation"},
		},
	}, textPrompt(func(args map[string]string) (string, error) {
		serial := args["serial"]
		if err := checkSerial(serial); err != nil {
			return "", err
		}
		reason := args["reason"]
		if reason == "" {
			reason = "not given; ask the user, defaulting to unspecified"
		}
		return fmt.Sprintf(`Revoke TrustMate certificate %s. Reason: %s.

1. Call get_certificate with serial %s and show the user its subject, profile and validity. Stop if it is already revoked.
2. Warn that revocation is permanent, and that revoking an API client certificate also cuts off that client's access. Ask the user to confirm. Do not revoke without confirmation.
3. Call revoke_certificate.
4. Call get_certificate again and confirm it now shows as revoked.`, serial, reason, serial), nil
	}))
}

func textPrompt(render func(map[string]string) (string, error)) mcp.PromptHandler {
	return func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		text, err := render(req.Params.Arguments)
		if err != nil {
			return nil, err
		}
		return &mcp.GetPromptResult{Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}}}, nil
	}
}

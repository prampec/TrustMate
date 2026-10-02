package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (h *harness) readResource(t *testing.T, uri string) (string, error) {
	t.Helper()
	res, err := h.session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		return "", err
	}
	if len(res.Contents) != 1 {
		t.Fatalf("%s: got %d contents, want 1", uri, len(res.Contents))
	}
	return res.Contents[0].Text, nil
}

func TestResourcesAreListed(t *testing.T) {
	h := newHarness(t, true)
	res, err := h.session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, r := range res.Resources {
		uris = append(uris, r.URI)
	}
	for _, want := range []string{"trustmate://ca/root.pem", "trustmate://ca/intermediate.pem", "trustmate://profiles", "trustmate://openapi.yaml"} {
		if !slices.Contains(uris, want) {
			t.Errorf("resources %v missing %s", uris, want)
		}
	}

	tmpls, err := h.session.ListResourceTemplates(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpls.ResourceTemplates) != 1 || tmpls.ResourceTemplates[0].URITemplate != "trustmate://certificates/{serial}" {
		t.Errorf("resource templates = %+v", tmpls.ResourceTemplates)
	}
}

func TestReadResources(t *testing.T) {
	h := newHarness(t, true)

	text, err := h.readResource(t, "trustmate://ca/intermediate.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "BEGIN CERTIFICATE") {
		t.Errorf("intermediate.pem resource = %q", text)
	}

	text, err = h.readResource(t, "trustmate://certificates/42")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, `"serial":"42"`) || h.fake.lastPath != "/v1/certificates/42" {
		t.Errorf("certificate resource = %q (server path %q)", text, h.fake.lastPath)
	}

	if _, err := h.readResource(t, "trustmate://certificates/..%2Faudit"); err == nil {
		t.Error("non-decimal serial was accepted")
	}
	if _, err := h.readResource(t, "trustmate://ca/root.pem"); err == nil {
		t.Error("expected the fake CA's missing root.pem to surface as an error")
	}
}

func promptNames(t *testing.T, h *harness) []string {
	t.Helper()
	res, err := h.session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range res.Prompts {
		names = append(names, p.Name)
	}
	return names
}

func TestPromptsRespectReadOnly(t *testing.T) {
	all := promptNames(t, newHarness(t, false))
	ro := promptNames(t, newHarness(t, true))
	for _, name := range []string{"certificate-status", "issue-certificate", "revoke-certificate"} {
		if !slices.Contains(all, name) {
			t.Errorf("full mode missing prompt %s: %v", name, all)
		}
	}
	if !slices.Equal(ro, []string{"certificate-status"}) {
		t.Errorf("read-only prompts = %v, want only certificate-status", ro)
	}
}

func TestPromptRendering(t *testing.T) {
	h := newHarness(t, false)
	ctx := context.Background()

	res, err := h.session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "revoke-certificate", Arguments: map[string]string{"serial": "123", "reason": "superseded"}})
	if err != nil {
		t.Fatal(err)
	}
	text := res.Messages[0].Content.(*mcp.TextContent).Text
	for _, want := range []string{"123", "superseded", "get_certificate", "revoke_certificate", "confirm"} {
		if !strings.Contains(text, want) {
			t.Errorf("revoke prompt missing %q:\n%s", want, text)
		}
	}

	res, err = h.session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "issue-certificate", Arguments: map[string]string{"common_name": "web01.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	text = res.Messages[0].Content.(*mcp.TextContent).Text
	if !strings.Contains(text, "preview_certificate") || !strings.Contains(text, `"web01.example.com"`) {
		t.Errorf("issue prompt:\n%s", text)
	}

	if _, err := h.session.GetPrompt(ctx, &mcp.GetPromptParams{Name: "certificate-status", Arguments: map[string]string{"serial": "abc"}}); err == nil {
		t.Error("non-decimal serial accepted by certificate-status prompt")
	}
}

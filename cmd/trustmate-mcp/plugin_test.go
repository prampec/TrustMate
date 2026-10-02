package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPluginManifestEnvMatchesServer guards the Claude Code plugin in
// plugins/trustmate against drift: every environment variable it sets
// must be one trustmate-mcp actually reads, or the setting would be
// silently ignored.
func TestPluginManifestEnvMatchesServer(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "plugins", "trustmate", ".claude-plugin", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		MCPServers map[string]struct {
			Command string            `json:"command"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
		UserConfig map[string]json.RawMessage `json:"userConfig"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	server, ok := manifest.MCPServers["trustmate"]
	if !ok || server.Command != "trustmate-mcp" {
		t.Fatalf("mcpServers.trustmate = %+v", server)
	}

	var sources strings.Builder
	for _, path := range []string{"main.go", filepath.Join("..", "..", "internal", "cliclient", "client.go")} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sources.Write(src)
	}
	for name, value := range server.Env {
		if !strings.Contains(sources.String(), `"`+name+`"`) {
			t.Errorf("plugin sets %s, which trustmate-mcp never reads", name)
		}
		key := strings.TrimSuffix(strings.TrimPrefix(value, "${user_config."), "}")
		if _, ok := manifest.UserConfig[key]; !ok {
			t.Errorf("%s references undeclared user_config %q", name, key)
		}
	}
}

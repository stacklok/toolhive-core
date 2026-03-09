// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// registryYAML is a realistic registry fixture that exercises the custom
// UnmarshalYAML logic (BaseServerMetadata fields are at the top level, not
// nested) as well as all registry accessor methods.
const registryYAML = `
version: "1.0.0"
last_updated: "2024-06-01T00:00:00Z"
servers:
  server-b:
    name: server-b
    description: Second container server
    tier: Community
    status: Active
    transport: stdio
    image: example/server-b:latest
    tools:
      - tool_b
    metadata:
      stars: 5
      last_updated: "2024-01-02T00:00:00Z"
  server-a:
    name: server-a
    description: First container server
    tier: Official
    status: Active
    transport: sse
    image: example/server-a:latest
    target_port: 8080
    tools:
      - tool_a1
      - tool_a2
    tags:
      - ai
    env_vars:
      - name: API_KEY
        description: API key
        required: true
        secret: true
remote_servers:
  remote-a:
    name: remote-a
    description: A remote server
    tier: Community
    status: Active
    transport: streamable-http
    url: https://api.example.com/mcp
    proxy_port: 9090
    headers:
      - name: X-API-Key
        description: API key header
        required: true
        secret: true
groups:
  - name: ai-group
    description: AI tools group
    servers:
      server-a:
        name: server-a
        description: First container server
        tier: Official
        status: Active
        transport: sse
        image: example/server-a:latest
    remote_servers:
      remote-a:
        name: remote-a
        description: A remote server
        tier: Community
        status: Active
        transport: streamable-http
        url: https://api.example.com/mcp
  - name: empty-group
    description: No servers yet
`

func parseTestRegistry(t *testing.T) *Registry {
	t.Helper()
	var reg Registry
	require.NoError(t, yaml.Unmarshal([]byte(registryYAML), &reg))
	return &reg
}

// TestRegistry_YAMLRoundTrip verifies that the custom UnmarshalYAML correctly
// hydrates both ImageMetadata and RemoteServerMetadata (including embedded
// BaseServerMetadata fields) from a flat YAML document.
func TestRegistry_YAMLRoundTrip(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	// Container server – base fields promoted via UnmarshalYAML
	sa := reg.Servers["server-a"]
	require.NotNil(t, sa)
	assert.Equal(t, "server-a", sa.Name)
	assert.Equal(t, "Official", sa.Tier)
	assert.Equal(t, "sse", sa.Transport)
	assert.Equal(t, "example/server-a:latest", sa.Image)
	assert.Equal(t, 8080, sa.TargetPort)
	assert.Equal(t, []string{"tool_a1", "tool_a2"}, sa.Tools)
	assert.Equal(t, []string{"ai"}, sa.Tags)
	require.Len(t, sa.EnvVars, 1)
	assert.Equal(t, "API_KEY", sa.EnvVars[0].Name)
	assert.True(t, sa.EnvVars[0].Required)
	assert.True(t, sa.EnvVars[0].Secret)

	// Remote server – base fields promoted via UnmarshalYAML
	ra := reg.RemoteServers["remote-a"]
	require.NotNil(t, ra)
	assert.Equal(t, "remote-a", ra.Name)
	assert.Equal(t, "streamable-http", ra.Transport)
	assert.Equal(t, "https://api.example.com/mcp", ra.URL)
	assert.Equal(t, 9090, ra.ProxyPort)
	require.Len(t, ra.Headers, 1)
	assert.Equal(t, "X-API-Key", ra.Headers[0].Name)
	assert.True(t, ra.Headers[0].Secret)
}

// TestRegistry_GetAllServers exercises the unified server listing through
// GetAllServers and confirms IsRemote distinguishes the two kinds.
func TestRegistry_GetAllServers(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	all := reg.GetAllServers()
	assert.Len(t, all, 3) // server-a, server-b, remote-a

	var remotes, containers int
	for _, s := range all {
		if s.IsRemote() {
			remotes++
		} else {
			containers++
		}
	}
	assert.Equal(t, 1, remotes)
	assert.Equal(t, 2, containers)
}

// TestRegistry_GetServerByName exercises server lookup and verifies that
// metadata returned through the ServerMetadata interface is correct.
func TestRegistry_GetServerByName(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	tests := []struct {
		name     string
		wantName string
		remote   bool
		found    bool
	}{
		{"server-a", "server-a", false, true},
		{"remote-a", "remote-a", true, true},
		{"missing", "", false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv, ok := reg.GetServerByName(tc.name)
			assert.Equal(t, tc.found, ok)
			if tc.found {
				assert.Equal(t, tc.wantName, srv.GetName())
				assert.Equal(t, tc.remote, srv.IsRemote())
			}
		})
	}
}

// TestRegistry_GetAllServers_SortedByName exercises SortServersByName on the
// full server list, ensuring deterministic ordering.
func TestRegistry_GetAllServers_SortedByName(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	all := reg.GetAllServers()
	SortServersByName(all)

	names := make([]string, len(all))
	for i, s := range all {
		names[i] = s.GetName()
	}
	assert.Equal(t, []string{"remote-a", "server-a", "server-b"}, names)
}

// TestRegistry_Groups exercises group lookup and group server enumeration.
func TestRegistry_Groups(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	assert.Len(t, reg.GetAllGroups(), 2)

	g, ok := reg.GetGroupByName("ai-group")
	require.True(t, ok)
	assert.Equal(t, "AI tools group", g.Description)

	servers := g.GetAllGroupServers()
	assert.Len(t, servers, 2)

	_, ok = reg.GetGroupByName("nonexistent")
	assert.False(t, ok)
}

// TestRegistry_EmptyGroup verifies GetAllGroupServers on a group with no servers.
func TestRegistry_EmptyGroup(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	g, ok := reg.GetGroupByName("empty-group")
	require.True(t, ok)
	assert.Empty(t, g.GetAllGroupServers())
}

// TestRegistry_ServerMetadataInterface verifies that iterating all servers via
// the ServerMetadata interface returns sensible values – the way display/filter
// code in consuming packages calls these methods.
func TestRegistry_ServerMetadataInterface(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	all := reg.GetAllServers()
	SortServersByName(all)

	// Spot-check server-a through the interface (covers all BaseServerMetadata getters)
	var sa ServerMetadata
	for _, s := range all {
		if s.GetName() == "server-a" {
			sa = s
			break
		}
	}
	require.NotNil(t, sa)
	assert.Equal(t, "First container server", sa.GetDescription())
	assert.Equal(t, "Official", sa.GetTier())
	assert.Equal(t, "Active", sa.GetStatus())
	assert.Equal(t, "sse", sa.GetTransport())
	assert.Equal(t, []string{"tool_a1", "tool_a2"}, sa.GetTools())
	assert.Equal(t, []string{"ai"}, sa.GetTags())
	assert.Equal(t, "", sa.GetTitle())    // not set in fixture
	assert.Equal(t, "", sa.GetOverview()) // not set in fixture
	assert.Equal(t, "", sa.GetRepositoryURL())
	assert.Nil(t, sa.GetToolDefinitions())
	assert.Nil(t, sa.GetCustomMetadata())
	assert.Nil(t, sa.GetMetadata())
	assert.False(t, sa.IsRemote())
	require.Len(t, sa.GetEnvVars(), 1)
	assert.Equal(t, "API_KEY", sa.GetEnvVars()[0].Name)

	// Spot-check remote-a through the interface
	var ra ServerMetadata
	for _, s := range all {
		if s.GetName() == "remote-a" {
			ra = s
			break
		}
	}
	require.NotNil(t, ra)
	assert.True(t, ra.IsRemote())
	assert.Equal(t, "A remote server", ra.GetDescription())
	assert.Empty(t, ra.GetEnvVars())

	// GetRawImplementation on the concrete type
	concrete, ok := reg.RemoteServers["remote-a"]
	require.True(t, ok)
	assert.Equal(t, concrete, concrete.GetRawImplementation())
}

// TestMetadata_ParsedTime exercises ParsedTime through a real server's metadata.
func TestMetadata_ParsedTime(t *testing.T) {
	t.Parallel()
	reg := parseTestRegistry(t)

	srv := reg.Servers["server-b"]
	require.NotNil(t, srv.Metadata)

	ts, err := srv.Metadata.ParsedTime()
	require.NoError(t, err)
	assert.Equal(t, 2024, ts.Year())
	assert.Equal(t, 2, ts.Day())

	// Invalid timestamp produces an error
	m := &Metadata{LastUpdated: "not-a-date"}
	_, err = m.ParsedTime()
	assert.Error(t, err)
}

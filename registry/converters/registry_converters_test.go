// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	registry "github.com/stacklok/toolhive-core/registry/types"
)

func TestNewUpstreamRegistryFromToolhiveRegistry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		toolhiveReg *registry.Registry
		expectError bool
		validate    func(*testing.T, *registry.UpstreamRegistry)
	}{
		{
			name: "successful conversion with container servers",
			toolhiveReg: &registry.Registry{
				Version:     "1.0.0",
				LastUpdated: "2024-01-01T00:00:00Z",
				Servers: map[string]*registry.ImageMetadata{
					"test-server": {
						BaseServerMetadata: registry.BaseServerMetadata{
							Name:        "test-server",
							Description: "A test server",
							Tier:        "Community",
							Status:      "Active",
							Transport:   "stdio",
							Tools:       []string{"test_tool"},
						},
						Image: "test/image:latest",
					},
				},
				RemoteServers: make(map[string]*registry.RemoteServerMetadata),
			},
			expectError: false,
			validate: func(t *testing.T, sr *registry.UpstreamRegistry) {
				t.Helper()
				assert.Equal(t, "1.0.0", sr.Version)
				assert.Equal(t, "2024-01-01T00:00:00Z", sr.Meta.LastUpdated)
				assert.Len(t, sr.Data.Servers, 1)
				assert.Contains(t, sr.Data.Servers[0].Name, "test-server")
				assert.Equal(t, "A test server", sr.Data.Servers[0].Description)
			},
		},
		{
			name: "successful conversion with remote servers",
			toolhiveReg: &registry.Registry{
				Version:     "1.0.0",
				LastUpdated: "2024-01-01T00:00:00Z",
				Servers:     make(map[string]*registry.ImageMetadata),
				RemoteServers: map[string]*registry.RemoteServerMetadata{
					"remote-server": {
						BaseServerMetadata: registry.BaseServerMetadata{
							Name:        "remote-server",
							Description: "A remote server",
							Tier:        "Community",
							Status:      "Active",
							Transport:   "sse",
							Tools:       []string{"remote_tool"},
						},
						URL: "https://example.com",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, sr *registry.UpstreamRegistry) {
				t.Helper()
				assert.Len(t, sr.Data.Servers, 1)
				assert.Contains(t, sr.Data.Servers[0].Name, "remote-server")
			},
		},
		{
			name: "empty registry",
			toolhiveReg: &registry.Registry{
				Version:       "1.0.0",
				LastUpdated:   "2024-01-01T00:00:00Z",
				Servers:       make(map[string]*registry.ImageMetadata),
				RemoteServers: make(map[string]*registry.RemoteServerMetadata),
			},
			expectError: false,
			validate: func(t *testing.T, sr *registry.UpstreamRegistry) {
				t.Helper()
				assert.Empty(t, sr.Data.Servers)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := NewUpstreamRegistryFromToolhiveRegistry(tt.toolhiveReg)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

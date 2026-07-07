// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPlugin_MarshalRoundTrip verifies that a Plugin marshals to JSON and back
// preserving all fields, and that omitempty fields are omitted when unset.
func TestPlugin_MarshalRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("full plugin round trip", func(t *testing.T) {
		t.Parallel()
		plugin := &Plugin{
			Namespace:   testNamespace,
			Name:        testPluginName,
			Description: testLongDesc,
			Version:     testVersion,
			Status:      testStatusActive,
			Title:       "PDF Processor",
			License:     "Apache-2.0",
			Repository: &SkillRepository{
				URL:  "https://github.com/stacklok/plugins/pdf-processor",
				Type: testRegistryTypeGit,
			},
			Icons: []SkillIcon{
				{
					Src:   "https://example.com/icon.png",
					Size:  "64x64",
					Type:  "image/png",
					Label: "PDF icon",
				},
			},
			Packages: []SkillPackage{
				{
					RegistryType: testRegistryType,
					Identifier:   testPluginIdentifier,
					Digest:       "sha256:abc123",
					MediaType:    "application/vnd.stacklok.plugin.v1",
				},
			},
			Metadata: map[string]any{
				"author": "Stacklok",
			},
			Meta: map[string]any{
				testNamespace: map[string]any{},
			},
		}

		jsonData, err := json.Marshal(plugin)
		require.NoError(t, err)

		var decoded Plugin
		require.NoError(t, json.Unmarshal(jsonData, &decoded))
		assert.Equal(t, plugin.Namespace, decoded.Namespace)
		assert.Equal(t, plugin.Name, decoded.Name)
		assert.Equal(t, plugin.Description, decoded.Description)
		assert.Equal(t, plugin.Version, decoded.Version)
		assert.Equal(t, plugin.Status, decoded.Status)
		assert.Equal(t, plugin.Title, decoded.Title)
		assert.Equal(t, plugin.License, decoded.License)
		require.NotNil(t, decoded.Repository)
		assert.Equal(t, plugin.Repository.URL, decoded.Repository.URL)
		assert.Equal(t, plugin.Repository.Type, decoded.Repository.Type)
		require.Len(t, decoded.Icons, 1)
		assert.Equal(t, plugin.Icons[0].Src, decoded.Icons[0].Src)
		assert.Equal(t, plugin.Icons[0].Size, decoded.Icons[0].Size)
		assert.Equal(t, plugin.Icons[0].Type, decoded.Icons[0].Type)
		assert.Equal(t, plugin.Icons[0].Label, decoded.Icons[0].Label)
		require.Len(t, decoded.Packages, 1)
		assert.Equal(t, plugin.Packages[0].RegistryType, decoded.Packages[0].RegistryType)
		assert.Equal(t, plugin.Packages[0].Identifier, decoded.Packages[0].Identifier)
		assert.Equal(t, plugin.Packages[0].Digest, decoded.Packages[0].Digest)
		assert.Equal(t, plugin.Packages[0].MediaType, decoded.Packages[0].MediaType)
		assert.Equal(t, plugin.Metadata["author"], decoded.Metadata["author"])
		assert.Contains(t, decoded.Meta, testNamespace)
	})

	t.Run("omitempty omits optional fields", func(t *testing.T) {
		t.Parallel()
		plugin := &Plugin{
			Namespace:   testNamespace,
			Name:        testPluginName,
			Description: testLongDesc,
			Version:     testVersion,
		}

		jsonData, err := json.Marshal(plugin)
		require.NoError(t, err)
		str := string(jsonData)
		assert.NotContains(t, str, errKeyStatus)
		assert.NotContains(t, str, "title")
		assert.NotContains(t, str, "license")
		assert.NotContains(t, str, "repository")
		assert.NotContains(t, str, "icons")
		assert.NotContains(t, str, "packages")
		assert.NotContains(t, str, "metadata")
		assert.NotContains(t, str, "_meta")
	})
}

// TestPlugin_Validate tests the Validate method on the Plugin struct.
func TestPlugin_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		plugin        *Plugin
		wantErr       bool
		errorContains string
	}{
		{
			name: "valid minimal plugin",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testLongDesc,
				Version:     testVersion,
			},
			wantErr: false,
		},
		{
			name: "valid full plugin",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testLongDesc,
				Version:     testVersion,
				Status:      testStatusActive,
				Title:       "PDF Processor",
				License:     "Apache-2.0",
				Repository: &SkillRepository{
					URL:  "https://github.com/stacklok/plugins/pdf-processor",
					Type: testRegistryTypeGit,
				},
				Icons: []SkillIcon{
					{Src: "https://example.com/icon.png"},
				},
				Packages: []SkillPackage{
					{
						RegistryType: testRegistryType,
						Identifier:   testPluginIdentifier,
					},
				},
				Metadata: map[string]any{"author": "Stacklok"},
				Meta:     map[string]any{testNamespace: map[string]any{}},
			},
			wantErr: false,
		},
		{
			name:          "empty struct",
			plugin:        &Plugin{},
			wantErr:       true,
			errorContains: errKeyNamespace,
		},
		{
			name: "missing namespace",
			plugin: &Plugin{
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
			},
			wantErr:       true,
			errorContains: errKeyNamespace,
		},
		{
			name: "missing name",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Description: testShortDesc,
				Version:     testVersion,
			},
			wantErr:       true,
			errorContains: errKeyName,
		},
		{
			name: "missing description",
			plugin: &Plugin{
				Namespace: testNamespace,
				Name:      testPluginName,
				Version:   testVersion,
			},
			wantErr:       true,
			errorContains: errKeyDescription,
		},
		{
			name: "missing version",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
			},
			wantErr:       true,
			errorContains: errKeyVersion,
		},
		{
			name: "invalid status enum",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
				Status:      "invalid-status",
			},
			wantErr:       true,
			errorContains: errKeyStatus,
		},
		{
			name: "invalid package registryType",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
				Packages: []SkillPackage{
					{RegistryType: "invalid"},
				},
			},
			wantErr:       true,
			errorContains: errKeyRegistryType,
		},
		{
			name: "invalid name pattern - uppercase",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        "MyPlugin",
				Description: testShortDesc,
				Version:     testVersion,
			},
			wantErr:       true,
			errorContains: errKeyName,
		},
		{
			name: "invalid name pattern - leading dash",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        "-plugin",
				Description: testShortDesc,
				Version:     testVersion,
			},
			wantErr:       true,
			errorContains: errKeyName,
		},
		{
			name: "valid status deprecated",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
				Status:      "deprecated",
			},
			wantErr: false,
		},
		{
			name: "valid status archived",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
				Status:      "archived",
			},
			wantErr: false,
		},
		{
			name: "package missing registryType",
			plugin: &Plugin{
				Namespace:   testNamespace,
				Name:        testPluginName,
				Description: testShortDesc,
				Version:     testVersion,
				Packages: []SkillPackage{
					{Identifier: "x"},
				},
			},
			wantErr:       true,
			errorContains: errKeyRegistryType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.plugin.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidatePluginBytes tests the ValidatePluginBytes function.
func TestValidatePluginBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		data          string
		wantErr       bool
		errorContains string
	}{
		{
			name: "valid minimal plugin",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables from PDF files",
				"version": "1.0.0"
			}`,
			wantErr: false,
		},
		{
			name: "valid full plugin with oci and git packages",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables from PDF files",
				"version": "1.0.0",
				"status": "active",
				"title": "PDF Processor",
				"license": "Apache-2.0",
				"repository": {
					"url": "https://github.com/stacklok/plugins/pdf-processor",
					"type": "git"
				},
				"icons": [
					{
						"src": "https://example.com/icon.png",
						"size": "64x64",
						"type": "image/png",
						"label": "PDF icon"
					}
				],
				"packages": [
					{
						"registryType": "oci",
						"identifier": "ghcr.io/stacklok/plugins/pdf-processor:1.0.0",
						"digest": "sha256:abc123",
						"mediaType": "application/vnd.stacklok.plugin.v1"
					},
					{
						"registryType": "git",
						"url": "https://github.com/stacklok/plugins/pdf-processor",
						"ref": "main",
						"commit": "abc123def456",
						"subfolder": "plugins/pdf-processor"
					}
				],
				"metadata": {
					"author": "Stacklok"
				},
				"_meta": {
					"io.github.stacklok": {}
				}
			}`,
			wantErr: false,
		},
		{
			name: "valid git package",
			data: `{
				"namespace": "io.github.user",
				"name": "my-plugin",
				"description": "A custom plugin from a git repository",
				"version": "abc123def",
				"packages": [
					{
						"registryType": "git",
						"url": "https://github.com/user/my-plugin",
						"ref": "main",
						"commit": "abc123def456",
						"subfolder": "plugins/my-plugin"
					}
				]
			}`,
			wantErr: false,
		},
		{
			name: "missing namespace",
			data: `{
				"name": "pdf-processor",
				"description": "Extract text and tables",
				"version": "1.0.0"
			}`,
			wantErr:       true,
			errorContains: errKeyNamespace,
		},
		{
			name: "missing name",
			data: `{
				"namespace": "io.github.stacklok",
				"description": "Extract text and tables",
				"version": "1.0.0"
			}`,
			wantErr:       true,
			errorContains: errKeyName,
		},
		{
			name: "missing description",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"version": "1.0.0"
			}`,
			wantErr:       true,
			errorContains: errKeyDescription,
		},
		{
			name: "missing version",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables"
			}`,
			wantErr:       true,
			errorContains: errKeyVersion,
		},
		{
			name: "invalid status",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables",
				"version": "1.0.0",
				"status": "invalid-status"
			}`,
			wantErr:       true,
			errorContains: errKeyStatus,
		},
		{
			name: "invalid registryType",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables",
				"version": "1.0.0",
				"packages": [
					{
						"registryType": "invalid"
					}
				]
			}`,
			wantErr:       true,
			errorContains: errKeyRegistryType,
		},
		{
			name:          "invalid JSON",
			data:          `{invalid json`,
			wantErr:       true,
			errorContains: "plugin schema validation failed",
		},
		{
			name: "invalid name pattern - uppercase",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "MyPlugin",
				"description": "Extract text and tables",
				"version": "1.0.0"
			}`,
			wantErr:       true,
			errorContains: errKeyName,
		},
		{
			name: "package missing registryType",
			data: `{
				"namespace": "io.github.stacklok",
				"name": "pdf-processor",
				"description": "Extract text and tables",
				"version": "1.0.0",
				"packages": [
					{
						"identifier": "ghcr.io/stacklok/plugins/pdf-processor:1.0.0"
					}
				]
			}`,
			wantErr:       true,
			errorContains: errKeyRegistryType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePluginBytes([]byte(tt.data))
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

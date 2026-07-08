// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"testing"
	"time"

	upstreamv0 "github.com/modelcontextprotocol/registry/pkg/api/v0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestUpstreamRegistry_JSONSerialization(t *testing.T) {
	t.Parallel()
	registry := &UpstreamRegistry{
		Schema:  UpstreamRegistrySchemaURL,
		Version: testVersion,
		Meta: UpstreamMeta{
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		Data: UpstreamData{
			Servers: []upstreamv0.ServerJSON{},
		},
	}

	// Test JSON marshaling
	jsonData, err := json.MarshalIndent(registry, "", "  ")
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), `"$schema"`)
	assert.Contains(t, string(jsonData), `"meta"`)
	assert.Contains(t, string(jsonData), `"data"`)

	// Test JSON unmarshaling
	var decoded UpstreamRegistry
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)
	assert.Equal(t, registry.Version, decoded.Version)
	assert.Equal(t, registry.Schema, decoded.Schema)
	assert.Equal(t, registry.Meta.LastUpdated, decoded.Meta.LastUpdated)
}

func TestUpstreamRegistry_YAMLSerialization(t *testing.T) {
	t.Parallel()
	registry := &UpstreamRegistry{
		Schema:  UpstreamRegistrySchemaURL,
		Version: testVersion,
		Meta: UpstreamMeta{
			LastUpdated: "2024-01-15T10:30:00Z",
		},
		Data: UpstreamData{
			Servers: []upstreamv0.ServerJSON{},
		},
	}

	// Test YAML marshaling
	yamlData, err := yaml.Marshal(registry)
	require.NoError(t, err)
	assert.Contains(t, string(yamlData), "meta:")
	assert.Contains(t, string(yamlData), "data:")

	// Test YAML unmarshaling
	var decoded UpstreamRegistry
	err = yaml.Unmarshal(yamlData, &decoded)
	require.NoError(t, err)
	assert.Equal(t, registry.Version, decoded.Version)
	assert.Equal(t, registry.Meta.LastUpdated, decoded.Meta.LastUpdated)
}

func TestUpstreamRegistry_SchemaField(t *testing.T) {
	t.Parallel()

	registry := &UpstreamRegistry{
		Schema:  UpstreamRegistrySchemaURL,
		Version: testVersion,
		Meta: UpstreamMeta{
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		Data: UpstreamData{
			Servers: []upstreamv0.ServerJSON{},
		},
	}

	// Verify schema field is correctly serialized with "$schema" key
	jsonData, err := json.Marshal(registry)
	require.NoError(t, err)
	assert.Contains(t, string(jsonData), `"$schema":"`+UpstreamRegistrySchemaURL+`"`)

	// Verify schema field can be deserialized
	var decoded UpstreamRegistry
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)
	assert.Equal(t, registry.Schema, decoded.Schema)
}

func TestRegistryMeta_TimeFormat(t *testing.T) {
	t.Parallel()

	// Test RFC3339 timestamp format
	timestamp := "2024-01-15T10:30:00Z"
	meta := UpstreamMeta{
		LastUpdated: timestamp,
	}

	jsonData, err := json.Marshal(meta)
	require.NoError(t, err)

	var decoded UpstreamMeta
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)
	assert.Equal(t, timestamp, decoded.LastUpdated)

	// Verify the timestamp is valid RFC3339
	parsedTime, err := time.Parse(time.RFC3339, decoded.LastUpdated)
	require.NoError(t, err)
	assert.NotZero(t, parsedTime)
}

func TestRegistryData_EmptyOptionalFields(t *testing.T) {
	t.Parallel()

	// Test that skills and plugins can be omitted (omitempty)
	data := UpstreamData{
		Servers: []upstreamv0.ServerJSON{},
	}

	jsonData, err := json.Marshal(data)
	require.NoError(t, err)

	// Skills should not appear in JSON when nil (omitempty behavior)
	assert.NotContains(t, string(jsonData), "skills")
	// Plugins should not appear in JSON when nil (omitempty behavior)
	assert.NotContains(t, string(jsonData), "plugins")

	// Test with empty slice - also omitted due to omitempty
	data.Skills = []Skill{}
	data.Plugins = []Plugin{}
	jsonData, err = json.Marshal(data)
	require.NoError(t, err)

	// Empty arrays are also omitted with omitempty
	assert.NotContains(t, string(jsonData), "skills")
	assert.NotContains(t, string(jsonData), "plugins")
}

func TestUpstreamRegistry_WithSkills(t *testing.T) {
	t.Parallel()
	reg := &UpstreamRegistry{
		Schema:  UpstreamRegistrySchemaURL,
		Version: testVersion,
		Meta: UpstreamMeta{
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		Data: UpstreamData{
			Servers: []upstreamv0.ServerJSON{},
			Skills: []Skill{
				{
					Namespace:   testNamespace,
					Name:        testPluginName,
					Description: testLongDesc,
					Version:     testVersion,
					Status:      testStatusActive,
					Packages: []SkillPackage{
						{
							RegistryType: testRegistryType,
							Identifier:   "ghcr.io/stacklok/skills/pdf-processor:1.0.0",
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reg)
	require.NoError(t, err)

	var decoded UpstreamRegistry
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded.Data.Skills, 1)
	assert.Equal(t, testNamespace, decoded.Data.Skills[0].Namespace)
	assert.Equal(t, testPluginName, decoded.Data.Skills[0].Name)
	assert.Equal(t, testVersion, decoded.Data.Skills[0].Version)
	require.Len(t, decoded.Data.Skills[0].Packages, 1)
	assert.Equal(t, testRegistryType, decoded.Data.Skills[0].Packages[0].RegistryType)
}

func TestUpstreamRegistry_WithPlugins(t *testing.T) {
	t.Parallel()
	reg := &UpstreamRegistry{
		Schema:  UpstreamRegistrySchemaURL,
		Version: testVersion,
		Meta: UpstreamMeta{
			LastUpdated: time.Now().Format(time.RFC3339),
		},
		Data: UpstreamData{
			Servers: []upstreamv0.ServerJSON{},
			Plugins: []Plugin{
				{
					Namespace:   testNamespace,
					Name:        testPluginName,
					Description: testLongDesc,
					Version:     testVersion,
					Status:      testStatusActive,
					Packages: []SkillPackage{
						{
							RegistryType: testRegistryType,
							Identifier:   testPluginIdentifier,
						},
					},
				},
			},
		},
	}

	jsonData, err := json.Marshal(reg)
	require.NoError(t, err)

	var decoded UpstreamRegistry
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)
	require.Len(t, decoded.Data.Plugins, 1)
	assert.Equal(t, testNamespace, decoded.Data.Plugins[0].Namespace)
	assert.Equal(t, testPluginName, decoded.Data.Plugins[0].Name)
	assert.Equal(t, testVersion, decoded.Data.Plugins[0].Version)
	require.Len(t, decoded.Data.Plugins[0].Packages, 1)
	assert.Equal(t, testRegistryType, decoded.Data.Plugins[0].Packages[0].RegistryType)
}

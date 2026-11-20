// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompiledSchemaFor_ReusesCompilation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		schemaFile string
	}{
		{name: "upstream registry", schemaFile: "data/upstream-registry.schema.json"},
		{name: "publisher-provided", schemaFile: "data/publisher-provided.schema.json"},
		{name: "skill", schemaFile: "data/skill.schema.json"},
		{name: "server", schemaFile: "data/server.schema.json"},
		{name: "plugin", schemaFile: "data/plugin.schema.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			first, err := compiledSchemaFor(tt.schemaFile)
			require.NoError(t, err)
			require.NotNil(t, first)

			second, err := compiledSchemaFor(tt.schemaFile)
			require.NoError(t, err)
			assert.Same(t, first, second, "schema should be compiled once and reused")
		})
	}
}

func TestCompiledSchemaFor_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := compiledSchemaFor("data/does-not-exist.schema.json")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read embedded schema")

	_, again := compiledSchemaFor("data/does-not-exist.schema.json")
	assert.Equal(t, err, again, "a failed compilation should be reported the same way every time")
}

func TestValidateUpstreamRegistryBytes_Concurrent(t *testing.T) {
	t.Parallel()

	valid := []byte(registryWithExtensions(3, "active"))
	invalid := []byte(registryWithExtensions(3, "not-a-status"))

	const workers = 16
	var wg sync.WaitGroup
	errs := make([]error, workers*2)
	for i := range workers {
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs[2*i] = ValidateUpstreamRegistryBytes(valid)
		}()
		go func() {
			defer wg.Done()
			errs[2*i+1] = ValidateUpstreamRegistryBytes(invalid)
		}()
	}
	wg.Wait()

	for i := range workers {
		assert.NoError(t, errs[2*i], "valid registry should pass")
		require.Error(t, errs[2*i+1], "invalid registry should fail")
		assert.Contains(t, errs[2*i+1].Error(), "publisher-provided extensions validation failed")
	}
}

func BenchmarkValidateUpstreamRegistryBytes(b *testing.B) {
	for _, servers := range []int{1, 100} {
		data := []byte(registryWithExtensions(servers, "active"))
		b.Run(fmt.Sprintf("servers=%d", servers), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := ValidateUpstreamRegistryBytes(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// registryWithExtensions builds an upstream registry with the given number of
// servers, each carrying publisher-provided extensions with the given status.
func registryWithExtensions(servers int, status string) string {
	entries := make([]string, 0, servers)
	for i := range servers {
		entries = append(entries, fmt.Sprintf(`{
			"name": "io.github.stacklok/server-%d",
			"description": "Test server %d",
			"version": "1.0.0",
			"_meta": {
				"io.modelcontextprotocol.registry/publisher-provided": {
					"io.github.stacklok": {
						"ghcr.io/test/server-%d:v1.0.0": {
							"status": %q,
							"tier": "Official",
							"tools": ["tool1"]
						}
					}
				}
			}
		}`, i, i, i, status))
	}
	return fmt.Sprintf(`{
		"version": "1.0.0",
		"meta": {"last_updated": "2024-01-15T10:30:00Z"},
		"data": {"servers": [%s]}
	}`, strings.Join(entries, ","))
}

// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	registry "github.com/stacklok/toolhive-core/registry/types"
)

const (
	toolDefinitionsKey = "tool_definitions"
	schemaNameKey      = "name"
	schemaNumberKey    = "number"
)

func TestExtensionNumbersPreserved(t *testing.T) {
	t.Parallel()
	for _, number := range []string{"9007199254740993", "18446744073709551615", "0.12345678901234567890123456789", "1e400"} {
		t.Run(number, func(t *testing.T) {
			t.Parallel()
			ext := registry.ServerExtensions{
				Status:         defaultStatus,
				CustomMetadata: map[string]any{"value": json.Number(number)},
			}
			mapped := serverExtensionsToMap(ext)
			custom := mapped["custom_metadata"].(map[string]any)
			require.Equal(t, json.Number(number), custom["value"])
			decoded := remarshalToType[registry.ServerExtensions](mapped)
			require.Equal(t, json.Number(number), decoded.CustomMetadata["value"])

			server := createTestServerJSON()
			server.Meta.PublisherProvided = buildPublisherExtensionsMap(ext, testImageRef)
			got := getStacklokServerExtensions(server)
			require.NotNil(t, got)
			require.Equal(t, json.Number(number), got.CustomMetadata["value"])

			image, err := ServerJSONToImageMetadata(server)
			require.NoError(t, err)
			require.Equal(t, json.Number(number), image.CustomMetadata["value"])
			roundTrip, err := ImageMetadataToServerJSON(server.Name, image)
			require.NoError(t, err)
			encoded, err := json.Marshal(roundTrip)
			require.NoError(t, err)
			require.Contains(t, string(encoded), `"value":`+number)

			remote := &registry.RemoteServerMetadata{}
			remote.URL = "https://example.com/mcp"
			remote.Status = ext.Status
			remote.CustomMetadata = ext.CustomMetadata
			remoteServer, err := RemoteServerMetadataToServerJSON(server.Name, remote)
			require.NoError(t, err)
			remoteRoundTrip, err := ServerJSONToRemoteServerMetadata(remoteServer)
			require.NoError(t, err)
			require.Equal(t, json.Number(number), remoteRoundTrip.CustomMetadata["value"])
			encoded, err = json.Marshal(remoteRoundTrip)
			require.NoError(t, err)
			require.Contains(t, string(encoded), `"value":`+number)
		})
	}
}

func TestToolDefinitionNumbersPreserved(t *testing.T) {
	t.Parallel()

	for _, number := range []string{"9007199254740993", "18446744073709551615", "0.12345678901234567890123456789", "1e400"} {
		t.Run(number, func(t *testing.T) {
			t.Parallel()

			value := json.Number(number)
			extensions := map[string]any{
				"status": defaultStatus,
				toolDefinitionsKey: []any{map[string]any{
					schemaNameKey: testToolName,
					"_meta":       map[string]any{schemaNumberKey: value},
					"inputSchema": map[string]any{
						"type":                 "object",
						"$defs":                map[string]any{"definition": map[string]any{schemaNumberKey: value}},
						"properties":           map[string]any{"property": map[string]any{schemaNumberKey: value}},
						"additionalProperties": map[string]any{schemaNumberKey: value},
						"unmodeled":            value,
					},
					"outputSchema": map[string]any{
						"type":                 "object",
						"$defs":                map[string]any{"definition": map[string]any{schemaNumberKey: value}},
						"properties":           map[string]any{"property": map[string]any{schemaNumberKey: value}},
						"additionalProperties": map[string]any{schemaNumberKey: value},
						"unmodeled":            value,
					},
				}},
			}
			server := createTestServerJSON()
			server.Meta.PublisherProvided = map[string]any{
				registry.ToolHivePublisherNamespace: map[string]any{testImageRef: extensions},
			}
			decoded := getStacklokServerExtensions(server)
			require.NotNil(t, decoded)

			require.Len(t, decoded.ToolDefinitions, 1)
			tool := decoded.ToolDefinitions[0]
			require.Equal(t, value, tool.Meta.AdditionalFields[schemaNumberKey])
			assertSchemaNumbers(t, mcp.ToolArgumentsSchema(tool.InputSchema), value)
			assertSchemaNumbers(t, mcp.ToolArgumentsSchema(tool.OutputSchema), value)
		})
	}
}

func assertSchemaNumbers(t *testing.T, schema mcp.ToolArgumentsSchema, want json.Number) {
	t.Helper()
	require.Equal(t, want, schema.Defs["definition"].(map[string]any)[schemaNumberKey])
	require.Equal(t, want, schema.Properties["property"].(map[string]any)[schemaNumberKey])
	require.Equal(t, want, schema.AdditionalProperties.(map[string]any)[schemaNumberKey])
	require.Equal(t, string(want), string(schema.Extra["unmodeled"]))
}

func TestRemarshalToTypeReturnsZeroValueOnDecodeError(t *testing.T) {
	t.Parallel()

	got := remarshalToType[registry.ServerExtensions](map[string]any{
		"status": defaultStatus,
		"tools":  []any{1},
	})
	require.Equal(t, registry.ServerExtensions{}, got)
}

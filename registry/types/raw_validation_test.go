// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

const rawServerFields = `"name":"io.github.test/server","description":"Test server","version":"1.0.0"`

func rawRegistry(server string) string {
	return `{"version":"1.0.0","meta":{"last_updated":"2026-01-01T00:00:00Z"},"data":{"servers":[` + server + `]}}`
}

func TestRawJSONStrictBoundaries(t *testing.T) {
	t.Parallel()
	validators := []struct {
		name     string
		validate func([]byte) error
	}{
		{"server/policy-on", func(data []byte) error { return ValidateServerJSON(data, true) }},
		{"server/policy-off", func(data []byte) error { return ValidateServerJSON(data, false) }},
		{"registry", ValidateUpstreamRegistryBytes},
		{"extensions", ValidatePublisherProvidedExtensionsBytes},
		{"skill", ValidateSkillBytes},
		{"plugin", ValidatePluginBytes},
	}
	inputs := []struct{ name, data string }{
		{"empty", ""},
		{"malformed", `{"secret":`},
		{"trailing-garbage", `{} secret`},
		{"multiple-values", `{} {}`},
		{"duplicate", `{"secret":1,"secret":2}`},
		{"nested-duplicate", `{"custom":[{"secret":1,"secret":2}]}`},
		{"escaped-duplicate", `{"custom":[{"secret":1,"\u0073ecret":2}]}`},
		{"unicode-duplicate", `{"é":1,"\u00e9":2}`},
		{"surrogate-pair-duplicate", `{"😀":1,"\ud83d\ude00":2}`},
		{"invalid-utf8-value", "{\"key\":\"\xff\"}"},
		{"invalid-utf8-key", "{\"\xff\":1}"},
		{"high-surrogate", `{"key":"\ud800"}`},
		{"low-surrogate", `{"key":"\udc00"}`},
		{"surrogate-key", `{"\ud800":1}`},
		{"bad-surrogate-pair", `{"key":"\ud800\u0041"}`},
	}
	for _, validator := range validators {
		t.Run(validator.name, func(t *testing.T) {
			t.Parallel()
			for _, input := range inputs {
				t.Run(input.name, func(t *testing.T) {
					t.Parallel()
					err := validator.validate([]byte(input.data))
					require.ErrorContains(t, err, "invalid JSON")
					require.NotContains(t, err.Error(), "secret")
				})
			}
			t.Run("null", func(t *testing.T) {
				t.Parallel()
				require.Error(t, validator.validate([]byte(`null`)))
			})
		})
	}
}

func TestValidateServerJSONOriginalSchema(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, data string
		valid      bool
	}{
		{"valid", `{` + rawServerFields + `}`, true},
		{"whitespace", " \n{" + rawServerFields + "}\t\r\n", true},
		{"case-distinct", `{` + rawServerFields + `,"Name":123}`, true},
		{"unicode", `{` + rawServerFields + `,"custom":{"é":"\ud83d\ude00","é":"😀"}}`, true},
		{"object", `{}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"scalar", `42`, false},
		{"missing-name", `{"description":"test","version":"1"}`, false},
		{"missing-description", `{"name":"io.test/server","version":"1"}`, false},
		{"missing-version", `{"name":"io.test/server","description":"test"}`, false},
		{"wrong-type", `{"name":42,"description":"test","version":"1"}`, false},
		{"wrong-case-required", `{"Name":"io.test/server","description":"test","version":"1"}`, false},
		{"name-pattern", `{"name":"bad-name","description":"test","version":"1"}`, false},
		{"description-max", `{"name":"io.test/server","description":"` + strings.Repeat("a", 101) + `","version":"1"}`, false},
		{"title-max", `{` + rawServerFields + `,"title":"` + strings.Repeat("a", 101) + `"}`, false},
		{"packages-null", `{` + rawServerFields + `,"packages":null}`, false},
		{"packages-empty", `{` + rawServerFields + `,"packages":[]}`, true},
		{"invalid-package", `{` + rawServerFields + `,"packages":[{}]}`, false},
		{"invalid-remote", `{` + rawServerFields + `,"remotes":[{"type":"unknown","url":"https://example.com"}]}`, false},
		{"meta-null", `{` + rawServerFields + `,"_meta":null}`, false},
		{"publisher-null", `{` + rawServerFields + `,"_meta":{"` + PublisherProvidedKey + `":null}}`, false},
	}
	for _, tt := range tests {
		for _, policy := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/policy=%t", tt.name, policy), func(t *testing.T) {
				t.Parallel()
				err := ValidateServerJSON([]byte(tt.data), policy)
				if tt.valid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
				// Whole registries must apply the same original-byte server schema.
				err = ValidateUpstreamRegistryBytes([]byte(rawRegistry(tt.data)))
				if tt.valid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			})
		}
	}
}

func TestRawPublisherPolicy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, publisher string
		policyValid     bool
	}{
		{"empty", `{}`, true},
		{"custom-object", `{"com.example":{"arbitrary":[1,"x",null]}}`, true},
		{"case-distinct", `{"com.example":{"name":1,"Name":2}}`, true},
		{"string-namespace", `{"com.example":"secret"}`, false},
		{"number-namespace", `{"com.example":1}`, false},
		{"array-namespace", `{"com.example":[]}`, false},
		{"null-namespace", `{"com.example":null}`, false},
		{"toolhive-array", `{"io.github.stacklok":[]}`, false},
		{"toolhive-missing-status", `{"io.github.stacklok":{"image":{}}}`, false},
		{"toolhive-invalid-tier", `{"io.github.stacklok":{"image":{"status":"active","tier":"secret"}}}`, false},
		{"toolhive-valid", `{"io.github.stacklok":{"image":{"status":"active","custom_metadata":{"value":1e400}}}}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := `{` + rawServerFields + `,"_meta":{"` + PublisherProvidedKey + `":` + tt.publisher + `}}`
			require.NoError(t, ValidateServerJSON([]byte(server), false))
			for _, err := range []error{
				ValidateServerJSON([]byte(server), true),
				ValidatePublisherProvidedExtensionsBytes([]byte(tt.publisher)),
				ValidateUpstreamRegistryBytes([]byte(rawRegistry(server))),
			} {
				if tt.policyValid {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
					require.NotContains(t, err.Error(), "secret")
				}
			}
		})
	}
}

func TestRawNumbersPreserved(t *testing.T) {
	t.Parallel()
	for _, number := range []string{"9007199254740993", "18446744073709551615", "0.12345678901234567890123456789", "1e400"} {
		t.Run(number, func(t *testing.T) {
			t.Parallel()
			publisher := `{"io.github.stacklok":{"image":{"status":"active","custom_metadata":{"value":` + number + `}}},"com.example":{"value":` + number + `}}`
			server := `{` + rawServerFields + `,"custom":` + number + `,"_meta":{"` + PublisherProvidedKey + `":` + publisher + `}}`
			for _, policy := range []bool{false, true} {
				require.NoError(t, ValidateServerJSON([]byte(server), policy))
			}
			require.NoError(t, ValidateUpstreamRegistryBytes([]byte(rawRegistry(server))))
			require.NoError(t, ValidatePublisherProvidedExtensionsBytes([]byte(publisher)))
			var registry UpstreamRegistry
			require.NoError(t, decodeJSON([]byte(rawRegistry(server)), &registry))
			registry.Schema = UpstreamRegistrySchemaURL
			registry.Data.Servers[0].Schema = "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
			require.NoError(t, registry.Validate())
			encodedRegistry, err := json.Marshal(registry)
			require.NoError(t, err)
			require.Contains(t, string(encodedRegistry), `"value":`+number)
			for _, path := range []struct{ data, schema string }{
				{server, "data/server.schema.json"},
				{rawRegistry(server), "data/upstream-registry.schema.json"},
				{publisher, "data/publisher-provided.schema.json"},
			} {
				value, err := validateJSONAgainstSchema([]byte(path.data), path.schema, "validation")
				require.NoError(t, err)
				encoded, err := json.Marshal(value)
				require.NoError(t, err)
				require.Contains(t, string(encoded), `"value":`+number)
				var decoded map[string]any
				require.NoError(t, decodeJSON(encoded, &decoded))
				encodedAgain, err := json.Marshal(decoded)
				require.NoError(t, err)
				require.Equal(t, string(encoded), string(encodedAgain))
			}
		})
	}
}

func TestRawPackageVersionLength(t *testing.T) {
	t.Parallel()
	for _, length := range []int{255, 256} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			t.Parallel()
			server := `{` + rawServerFields + `,"packages":[{"registryType":"npm","identifier":"example","transport":{"type":"stdio"},"version":"` + strings.Repeat("v", length) + `"}]}`
			for _, policy := range []bool{false, true} {
				err := ValidateServerJSON([]byte(server), policy)
				if length == 255 {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			}
			err := ValidateUpstreamRegistryBytes([]byte(rawRegistry(server)))
			if length == 255 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestRawValidationRejectsFractionalPort(t *testing.T) {
	t.Parallel()
	publisher := `{"io.github.stacklok":{"image":{"status":"active","proxy_port":8080.0000000000000000000001}}}`
	server := `{` + rawServerFields + `,"_meta":{"` + PublisherProvidedKey + `":` + publisher + `}}`
	require.Error(t, ValidatePublisherProvidedExtensionsBytes([]byte(publisher)))
	require.NoError(t, ValidateServerJSON([]byte(server), false))
	require.Error(t, ValidateServerJSON([]byte(server), true))
	require.Error(t, ValidateUpstreamRegistryBytes([]byte(rawRegistry(server))))
}

func TestReleasedSchemaRejectsLeadingURLTemplates(t *testing.T) {
	t.Parallel()
	for _, transport := range []string{"sse", "streamable-http"} {
		t.Run(transport, func(t *testing.T) {
			t.Parallel()
			server := `{` + rawServerFields + `,"remotes":[{"type":"` + transport + `","url":"{base}/mcp"}]}`
			require.Error(t, ValidateServerJSON([]byte(server), false))
			require.Error(t, ValidateUpstreamRegistryBytes([]byte(rawRegistry(server))))
		})
	}
}

func TestRawValidationDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	data := []byte(`{` + rawServerFields + `,"_meta":{"` + PublisherProvidedKey + `":{"io.github.stacklok":{"image":{"status":"active","custom_metadata":{"value":1e400}}}}}}`)
	original := append([]byte(nil), data...)

	require.NoError(t, ValidateServerJSON(data, true))
	require.Equal(t, original, data)
}

func TestRawSchemaURLsAreOffline(t *testing.T) {
	t.Parallel()
	var requests atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer host.Close()
	for _, valid := range []bool{false, true} {
		fields := rawServerFields
		if !valid {
			fields = `"name":"bad-name","description":"test","version":"1"`
		}
		server := `{"$schema":"` + host.URL + `/server.schema.json",` + fields + `}`
		for _, policy := range []bool{false, true} {
			err := ValidateServerJSON([]byte(server), policy)
			if valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		}
		registry := `{"$schema":"` + host.URL + `/registry.schema.json",` + rawRegistry(server)[1:]
		err := ValidateUpstreamRegistryBytes([]byte(registry))
		if valid {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
		}
	}
	require.Zero(t, requests.Load())
}

func TestRawValidationErrorsRedacted(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"name":"SECRET_SERVER","description":"test","version":"1"}`,
		`{` + rawServerFields + `,"remotes":[{"type":"SECRET_TYPE","url":"SECRET_URL"}]}`,
		`{` + rawServerFields + `,"_meta":{"` + PublisherProvidedKey + `":{"SECRET_NAMESPACE":[],"io.github.stacklok":{"SECRET_IMAGE":{"status":"SECRET_STATUS","tier":"SECRET_TIER"}}}}}`,
	} {
		for _, err := range []error{ValidateServerJSON([]byte(input), true), ValidateUpstreamRegistryBytes([]byte(rawRegistry(input)))} {
			require.Error(t, err)
			require.NotContains(t, err.Error(), "SECRET")
		}
	}
}

func TestRawServerFixtures(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"../converters/testdata/image_to_server/expected_github.json",
		"../converters/testdata/remote_to_server/expected_example.json",
		"../converters/testdata/server_to_image/input_github.json",
		"../converters/testdata/server_to_remote/input_example.json",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(path)
			require.NoError(t, err)
			for _, policy := range []bool{false, true} {
				require.NoError(t, ValidateServerJSON(data, policy))
			}
		})
	}
}

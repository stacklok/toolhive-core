// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"encoding/base64"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"
)

// TestGetVerificationMaterialTlogEntriesMalformedAnnotations feeds the
// registry-supplied cosign bundle annotation with every malformed shape that
// previously hit a single-value type assertion. Each case must return an
// error — never panic — since the annotation is attacker-controlled.
func TestGetVerificationMaterialTlogEntriesMalformedAnnotations(t *testing.T) {
	t.Parallel()

	validBody := base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":"0.0.1","kind":"hashedrekord"}`))

	tests := []struct {
		name       string
		annotation string
	}{
		{name: caseNameNotJSON, annotation: `not json at all`},
		{name: "payload missing", annotation: `{"SignedEntryTimestamp":"c2ln"}`},
		{name: "payload not an object", annotation: `{"Payload":"scalar"}`},
		{name: "logIndex wrong type", annotation: `{"Payload":{"logIndex":"nope"}}`},
		{name: "logID wrong type", annotation: `{"Payload":{"logIndex":1,"logID":42}}`},
		{
			name:       "integratedTime wrong type",
			annotation: `{"Payload":{"logIndex":1,"logID":"abcd","integratedTime":"nope"}}`,
		},
		{
			name:       "SignedEntryTimestamp missing",
			annotation: `{"Payload":{"logIndex":1,"logID":"abcd","integratedTime":1}}`,
		},
		{
			name: "body wrong type",
			annotation: `{"Payload":{"logIndex":1,"logID":"abcd","integratedTime":1,"body":7},` +
				`"SignedEntryTimestamp":"c2ln"}`,
		},
		{
			name: "body decodes but apiVersion wrong type",
			annotation: `{"Payload":{"logIndex":1,"logID":"abcd","integratedTime":1,` +
				`"body":"` + base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":1,"kind":"x"}`)) + `"},` +
				`"SignedEntryTimestamp":"c2ln"}`,
		},
		{
			name: "body decodes but kind missing",
			annotation: `{"Payload":{"logIndex":1,"logID":"abcd","integratedTime":1,` +
				`"body":"` + base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":"0.0.1"}`)) + `"},` +
				`"SignedEntryTimestamp":"c2ln"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			layer := v1.Descriptor{
				Annotations: map[string]string{
					"dev.sigstore.cosign/bundle": tc.annotation,
				},
			}
			require.NotPanics(t, func() {
				_, err := getVerificationMaterialTlogEntries(layer)
				require.Error(t, err)
			})
		})
	}

	t.Run("well-formed annotation parses", func(t *testing.T) {
		t.Parallel()
		layer := v1.Descriptor{
			Annotations: map[string]string{
				"dev.sigstore.cosign/bundle": `{"Payload":{"logIndex":1,"logID":"abcd",` +
					`"integratedTime":1,"body":"` + validBody + `"},"SignedEntryTimestamp":"c2ln"}`,
			},
		}
		entries, err := getVerificationMaterialTlogEntries(layer)
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caseNameNotJSON labels the "input is not parseable JSON" case, which every
// parser in this package has to handle.
const caseNameNotJSON = "not json"

// TestCheckSimpleSigningBinding exercises the payload check directly, on the
// shapes a registry can actually serve — the payload is attacker-supplied
// data, so every rejection must be an error rather than a panic or a pass.
func TestCheckSimpleSigningBinding(t *testing.T) {
	t.Parallel()

	const artifactHex = "aaaa000000000000000000000000000000000000000000000000000000000000"
	const repo = "ghcr.io/example/artifact"
	good := fmt.Sprintf(
		`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":"sha256:%s"},`+
			`"type":%q}}`, repo, artifactHex, CosignSignatureType)

	t.Run("a payload naming this artifact is accepted", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, checkSimpleSigningBinding([]byte(good), DigestAlgorithmSHA256, artifactHex, repo))
	})

	t.Run("digest hex casing does not matter", func(t *testing.T) {
		t.Parallel()
		upper := strings.ToUpper(artifactHex)
		payload := fmt.Sprintf(
			`{"critical":{"image":{"docker-manifest-digest":"SHA256:%s"},"type":%q}}`,
			upper, CosignSignatureType)
		require.NoError(t, checkSimpleSigningBinding([]byte(payload), DigestAlgorithmSHA256, artifactHex, ""))
	})

	t.Run("a mismatched repository is a warning, not a rejection", func(t *testing.T) {
		t.Parallel()
		// The digest binding is what proves the signature covers this
		// artifact; docker-reference only records where the signer saw it.
		// Rejecting on it would break signature-preserving mirroring.
		require.NoError(t, checkSimpleSigningBinding(
			[]byte(good), DigestAlgorithmSHA256, artifactHex, "ghcr.io/somewhere/else"))

		unparseable := fmt.Sprintf(
			`{"critical":{"identity":{"docker-reference":"NOT A REF"},`+
				`"image":{"docker-manifest-digest":"sha256:%s"},"type":%q}}`,
			artifactHex, CosignSignatureType)
		require.NoError(t, checkSimpleSigningBinding(
			[]byte(unparseable), DigestAlgorithmSHA256, artifactHex, repo))
	})

	rejected := []struct {
		name    string
		payload string
	}{
		{name: "empty", payload: ""},
		{name: caseNameNotJSON, payload: "{"},
		{name: "json but not an object", payload: `"a string"`},
		{name: "no critical section", payload: `{}`},
		{
			name:    "wrong type",
			payload: fmt.Sprintf(`{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":"x"}}`, artifactHex),
		},
		{
			name:    "no digest",
			payload: fmt.Sprintf(`{"critical":{"image":{},"type":%q}}`, CosignSignatureType),
		},
		{
			name:    "digest without algorithm",
			payload: fmt.Sprintf(`{"critical":{"image":{"docker-manifest-digest":%q},"type":%q}}`, artifactHex, CosignSignatureType),
		},
		{
			name: "digest with empty hex",
			payload: fmt.Sprintf(`{"critical":{"image":{"docker-manifest-digest":"sha256:"},"type":%q}}`,
				CosignSignatureType),
		},
		{
			name: "different artifact",
			payload: fmt.Sprintf(
				`{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":%q}}`,
				strings.Repeat("bb", 32), CosignSignatureType),
		},
		{
			name: "different algorithm",
			payload: fmt.Sprintf(
				`{"critical":{"image":{"docker-manifest-digest":"sha512:%s"},"type":%q}}`,
				artifactHex, CosignSignatureType),
		},
	}
	for _, tc := range rejected {
		t.Run("rejected: "+tc.name, func(t *testing.T) {
			t.Parallel()
			require.NotPanics(t, func() {
				err := checkSimpleSigningBinding([]byte(tc.payload), DigestAlgorithmSHA256, artifactHex, repo)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrSignatureArtifactMismatch,
					"every rejection must be branchable as a binding failure")
			})
		})
	}
}

// TestArtifactDigestPolicy pins which digest each layout hands to Sigstore:
// the artifact digest when the bundle binds structurally, the payload digest
// when the signature covers a payload blob.
func TestArtifactDigestPolicy(t *testing.T) {
	t.Parallel()

	const artifactHex = "aaaa000000000000000000000000000000000000000000000000000000000000"
	artifactBytes, err := hex.DecodeString(artifactHex)
	require.NoError(t, err)

	t.Run("no payload binds the artifact digest directly", func(t *testing.T) {
		t.Parallel()
		opt, err := artifactDigestPolicy(nil, DigestAlgorithmSHA256, artifactBytes)
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("a payload naming this artifact is accepted", func(t *testing.T) {
		t.Parallel()
		payload := fmt.Sprintf(
			`{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":%q}}`,
			artifactHex, CosignSignatureType)
		opt, err := artifactDigestPolicy([]byte(payload), DigestAlgorithmSHA256, artifactBytes)
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("passing the payload's own digest is refused, and says so", func(t *testing.T) {
		t.Parallel()
		// The call shape callers used before the payload travelled with the
		// bundle. Refusing it is correct — a digest derived from the payload
		// says nothing about which artifact the payload names — but the error
		// has to point at the fix rather than read like a substituted
		// signature.
		payload := fmt.Sprintf(
			`{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":%q}}`,
			artifactHex, CosignSignatureType)
		sum := sha256.Sum256([]byte(payload))
		_, err := artifactDigestPolicy([]byte(payload), DigestAlgorithmSHA256, sum[:])
		require.ErrorIs(t, err, ErrSignatureArtifactMismatch)
		assert.ErrorContains(t, err, "pass the artifact's manifest digest")
	})

	t.Run("a payload naming a different artifact is refused", func(t *testing.T) {
		t.Parallel()
		payload := fmt.Sprintf(
			`{"critical":{"image":{"docker-manifest-digest":"sha256:%s"},"type":%q}}`,
			strings.Repeat("cc", 32), CosignSignatureType)
		_, err := artifactDigestPolicy([]byte(payload), DigestAlgorithmSHA256, artifactBytes)
		require.ErrorIs(t, err, ErrSignatureArtifactMismatch)
	})
}

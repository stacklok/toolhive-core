// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testArtifactHex is a stand-in artifact digest for the stored-form tests,
// which never touch a registry.
const testArtifactHex = "1111111111111111111111111111111111111111111111111111111111111111"

// attachAttestationReferrer signs an in-toto statement whose subject is the
// artifact digest and attaches the resulting Sigstore bundle as an OCI 1.1
// referrer of the artifact. It returns the signer's public key PEM.
//
// Unlike a cosign signature, this layout binds to the artifact structurally:
// the referrer is addressed by the artifact's digest, and the signed
// statement names that digest as its subject. Nothing about it needs the
// payload check the ".sig" path requires — which is exactly what these tests
// pin down.
func attachAttestationReferrer(t *testing.T, artifactRef name.Reference, artifact v1.Hash) []byte {
	t.Helper()

	keypair, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	statement := fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1",`+
			`"subject":[{"name":"artifact","digest":{"sha256":%q}}],`+
			`"predicateType":"https://example.com/test-predicate","predicate":{}}`,
		artifact.Hex)
	pb, err := sign.Bundle(
		&sign.DSSEData{Data: []byte(statement), PayloadType: "application/vnd.in-toto+json"},
		keypair, sign.BundleOptions{})
	require.NoError(t, err)
	bun, err := bundle.NewBundle(pb)
	require.NoError(t, err)
	rawBundle, err := bun.MarshalJSON()
	require.NoError(t, err)

	layer := static.NewLayer(rawBundle, types.MediaType(MediaTypeSigstoreBundleV03JSON))
	refImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:     layer,
		MediaType: types.MediaType(MediaTypeSigstoreBundleV03JSON),
	})
	require.NoError(t, err)
	refImg = mutate.MediaType(refImg, types.OCIManifestSchema1)
	// The config media type is what surfaces as the referrer descriptor's
	// artifactType — how cosign v2 marks an OCI 1.1 bundle, and what the
	// referrers scan filters on.
	refImg = mutate.ConfigMediaType(refImg, types.MediaType(MediaTypeSigstoreBundleV03JSON))

	// Publish it through the referrers tag schema rather than remote.Write's
	// subject handling: the in-process test registry implements neither the
	// referrers API nor subject-driven index maintenance, and the tag schema
	// is the fallback go-containerregistry uses against exactly such
	// registries.
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: refImg})
	repo := artifactRef.Context()
	require.NoError(t, remote.WriteIndex(referrersTag(repo, artifact), index))

	pubPEM, err := keypair.GetPublicKeyPem()
	require.NoError(t, err)
	return []byte(pubPEM)
}

// referrersTag is the OCI distribution-spec referrers tag schema —
// "sha256-<hex>", the fallback go-containerregistry reads when a registry
// does not implement the referrers API.
func referrersTag(repo name.Repository, artifact v1.Hash) name.Tag {
	return repo.Tag(fmt.Sprint(artifact.Algorithm, "-", artifact.Hex))
}

// TestRetrieveAttestationBundleRoundTrip pins the referrer path: it was
// already bound to the artifact digest by construction and must stay that
// way, persisting as bare Sigstore bundle JSON with no payload wrapper.
func TestRetrieveAttestationBundleRoundTrip(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/attested")
	pubPEM := attachAttestationReferrer(t, parsed, d)

	bundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err, "an attestation referrer must be retrievable")
	require.Len(t, bundles, 1)
	assert.Equal(t, d.Hex, bundles[0].DigestHex, "an attestation bundle binds the artifact digest")
	assert.Empty(t, bundles[0].SimpleSigningPayload,
		"an attestation carries its own subject; it needs no simple-signing payload")

	// Persisted as a plain Sigstore bundle — no envelope, so bundles stored
	// by earlier versions keep parsing and third-party tooling keeps working.
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	require.NoError(t, json.Unmarshal(bundles[0].Raw, &probe))
	assert.NotEqual(t, StoredBundleMediaType, probe.MediaType)

	_, err = VerifyBundleWithKey(bundles[0], pubPEM)
	require.NoError(t, err, "an attestation bundle must verify against the signing key")

	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, d.String(), pubPEM)
	require.NoError(t, err, "the stored attestation bundle must re-verify against the artifact digest")
}

// TestRetrieveBundlesReturnsBothLayouts covers discovery when an artifact
// carries an attestation referrer AND a cosign signature: both are returned,
// with the structurally-bound referrer first. Returning only whichever was
// found first would let whoever writes the mutable ".sig" tag decide which
// signature a verifier ever sees.
func TestRetrieveBundlesReturnsBothLayouts(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/both")
	attestationPub := attachAttestationReferrer(t, parsed, d)
	sigPub := attachKeySignature(t, sigTag(parsed, d), simpleSigningPayloadFor(parsed.Context().Name(), d))

	bundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err)
	require.Len(t, bundles, 2, "both layouts must be discovered")

	assert.Empty(t, bundles[0].SimpleSigningPayload, "the attestation referrer comes first")
	assert.NotEmpty(t, bundles[1].SimpleSigningPayload, "the cosign signature comes second")

	for i, pub := range [][]byte{attestationPub, sigPub} {
		assert.Equal(t, d.Hex, bundles[i].DigestHex, "every bundle binds the artifact digest")
		_, err := VerifyBundleWithKey(bundles[i], pub)
		require.NoError(t, err)
		_, err = VerifyBundleOfflineWithKey(bundles[i].Raw, d.String(), pub)
		require.NoError(t, err)
	}
}

// TestRetrieveBundlesKeepsAttestationWhenSignatureIsSubstituted is the
// defence-in-depth half of the reordering: a substituted cosign signature is
// dropped, but it must not take a genuine attestation down with it.
func TestRetrieveBundlesKeepsAttestationWhenSignatureIsSubstituted(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	signed := pushKeySignedArtifact(t, host, "test/signed")

	victim, victimDigest := pushArtifact(t, host, "test/attested")
	attestationPub := attachAttestationReferrer(t, victim, victimDigest)

	stolen, err := remote.Image(sigTag(signed.parsed, signed.digest))
	require.NoError(t, err)
	require.NoError(t, remote.Write(sigTag(victim, victimDigest), stolen))

	bundles, err := RetrieveBundles(t.Context(), victim.Name(), nil)
	require.NoError(t, err, "a genuine attestation must survive a substituted cosign signature")
	require.Len(t, bundles, 1, "the substituted signature must be dropped")
	_, err = VerifyBundleWithKey(bundles[0], attestationPub)
	require.NoError(t, err)
}

// TestStoredBundleRoundTrip covers the persisted form directly: what
// EncodeStoredBundle writes, DecodeStoredBundle must read back unchanged,
// for both shapes.
func TestStoredBundleRoundTrip(t *testing.T) {
	t.Parallel()

	bundleJSON, _, _ := signTestBundle(t, []byte("content"))
	payload := []byte(`{"critical":{"type":"cosign container image signature"}}`)
	artifactDigest := DigestAlgorithmSHA256 + ":" + testArtifactHex

	t.Run("without a payload the bundle JSON is stored verbatim", func(t *testing.T) {
		t.Parallel()
		raw, err := EncodeStoredBundle(bundleJSON, nil)
		require.NoError(t, err)
		assert.Equal(t, bundleJSON, raw)

		decoded, err := DecodeStoredBundle(raw, artifactDigest)
		require.NoError(t, err)
		assert.Empty(t, decoded.SimpleSigningPayload)
		assert.Equal(t, testArtifactHex, decoded.DigestHex)
		assert.Equal(t, DigestAlgorithmSHA256, decoded.DigestAlgo)
		require.NotNil(t, decoded.Parsed)
	})

	t.Run("with a payload both halves round-trip", func(t *testing.T) {
		t.Parallel()
		raw, err := EncodeStoredBundle(bundleJSON, payload)
		require.NoError(t, err)

		decoded, err := DecodeStoredBundle(raw, artifactDigest)
		require.NoError(t, err)
		assert.Equal(t, payload, decoded.SimpleSigningPayload,
			"the payload must come back byte-identical: the signature is checked against its digest")
		require.NotNil(t, decoded.Parsed)
		assert.Equal(t, testArtifactHex, decoded.DigestHex)
	})

	t.Run("a non-JSON bundle is refused rather than wrapped", func(t *testing.T) {
		t.Parallel()
		_, err := EncodeStoredBundle([]byte("not json"), payload)
		require.Error(t, err)
	})

	t.Run("malformed stored forms are rejected", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct{ name, raw string }{
			{name: caseNameNotJSON, raw: "{"},
			{
				name: "envelope without a payload",
				raw:  `{"mediaType":` + fmt.Sprintf("%q", StoredBundleMediaType) + `,"bundle":{}}`,
			},
			{
				name: "envelope with an unparseable bundle",
				raw: `{"mediaType":` + fmt.Sprintf("%q", StoredBundleMediaType) +
					`,"bundle":{"nope":1},"simpleSigningPayload":"e30="}`,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				_, err := DecodeStoredBundle([]byte(tc.raw), artifactDigest)
				require.Error(t, err)
			})
		}
	})

	t.Run("a malformed artifact digest is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := DecodeStoredBundle(bundleJSON, testArtifactHex)
		require.ErrorContains(t, err, "<algorithm>:<hex>")
	})
}

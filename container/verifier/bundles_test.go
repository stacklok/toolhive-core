// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signTestBundle signs payload with a fresh ephemeral key and returns the
// serialized bundle, the signer's public key PEM, and the payload digest.
// testWorkflowIdentity mirrors the workflow-path fixture used by the
// package's integration tests.
const testWorkflowIdentity = "/.github/workflows/release.yml"

func signTestBundle(t *testing.T, payload []byte) (raw []byte, pubPEM string, digestHex string) {
	t.Helper()

	keypair, err := sign.NewEphemeralKeypair(nil)
	require.NoError(t, err)

	pb, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, sign.BundleOptions{})
	require.NoError(t, err)

	parsed, err := bundle.NewBundle(pb)
	require.NoError(t, err)
	rawBytes, err := json.Marshal(parsed)
	require.NoError(t, err)

	pem, err := keypair.GetPublicKeyPem()
	require.NoError(t, err)

	digest := sha256.Sum256(payload)
	return rawBytes, pem, hex.EncodeToString(digest[:])
}

// TestKeySignedBundleRoundTrip is the contract downstream signing flows rely
// on: a bundle produced by sigstore-go's signing path with a plain key pair
// verifies through this package's exported API using PublicKeyMaterial.
func TestKeySignedBundleRoundTrip(t *testing.T) {
	t.Parallel()

	payload := []byte("skill artifact digest payload")
	raw, pubPEM, digestHex := signTestBundle(t, payload)

	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw))

	result, err := VerifyBundleWithKey(Bundle{
		Parsed:     parsed,
		Raw:        raw,
		DigestAlgo: DigestAlgorithmSHA256,
		DigestHex:  digestHex,
	}, []byte(pubPEM))
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestKeySignedBundleRejectsWrongDigest(t *testing.T) {
	t.Parallel()

	raw, pubPEM, _ := signTestBundle(t, []byte("original content"))
	otherDigest := sha256.Sum256([]byte("tampered content"))

	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw))

	_, err := VerifyBundleWithKey(Bundle{
		Parsed:     parsed,
		DigestAlgo: DigestAlgorithmSHA256,
		DigestHex:  hex.EncodeToString(otherDigest[:]),
	}, []byte(pubPEM))
	require.Error(t, err, "a bundle must not verify against a digest it did not sign")
}

func TestKeySignedBundleRejectsWrongKey(t *testing.T) {
	t.Parallel()

	raw, _, digestHex := signTestBundle(t, []byte("content"))
	// A different signer's public key must not verify this bundle.
	_, otherPubPEM, _ := signTestBundle(t, []byte("unrelated"))

	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw))

	_, err := VerifyBundleWithKey(Bundle{
		Parsed:     parsed,
		DigestAlgo: DigestAlgorithmSHA256,
		DigestHex:  digestHex,
	}, []byte(otherPubPEM))
	assert.ErrorIs(t, err, ErrVerificationFailed)
	require.Error(t, err)
}

func TestOfflineTrustedMaterial(t *testing.T) {
	t.Parallel()

	tm, err := OfflineTrustedMaterial()
	require.NoError(t, err, "the embedded trusted root must parse")
	require.NotNil(t, tm)
	assert.NotEmpty(t, tm.FulcioCertificateAuthorities(),
		"the public-good trusted root carries Fulcio CAs")
	assert.NotEmpty(t, tm.RekorLogs(),
		"the public-good trusted root carries Rekor transparency logs")
}

func TestVerifyBundleOfflineParsesStoredBundles(t *testing.T) {
	t.Parallel()

	// A stored key-signed bundle fails against the Fulcio trusted root (no
	// certificate), but must fail at verification — not at parsing — which
	// proves the offline path round-trips the stored Raw form.
	raw, _, digestHex := signTestBundle(t, []byte("content"))
	_, err := VerifyBundleOffline(raw, DigestAlgorithmSHA256+":"+digestHex, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "parsing stored bundle",
		"a well-formed stored bundle must reach verification")
	assert.ErrorIs(t, err, ErrVerificationFailed,
		"a verification failure must be branchable via the sentinel")

	_, err = VerifyBundleOffline([]byte("not json"), DigestAlgorithmSHA256+":"+digestHex, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing stored bundle")
	assert.NotErrorIs(t, err, ErrVerificationFailed,
		"malformed input is not a verification failure")

	_, err = VerifyBundleOffline(raw, digestHex, nil)
	require.Error(t, err, "a digest without an <algorithm>: prefix must be rejected")
}

func TestIdentityPolicyOption(t *testing.T) {
	t.Parallel()

	t.Run("nil expected yields a TOFU policy", func(t *testing.T) {
		t.Parallel()
		opt, err := identityPolicyOption(nil)
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("plain identity binds SAN exactly", func(t *testing.T) {
		t.Parallel()
		opt, err := identityPolicyOption(&Identity{
			SignerIdentity: "dev@example.com",
			CertIssuer:     "https://accounts.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("github actions identity binds SAN by repo-anchored prefix", func(t *testing.T) {
		t.Parallel()
		opt, err := identityPolicyOption(&Identity{
			SignerIdentity:      testWorkflowIdentity,
			CertIssuer:          githubTokenIssuer,
			SourceRepositoryURI: "https://github.com/org/repo",
		})
		require.NoError(t, err)
		require.NotNil(t, opt)
	})

	t.Run("empty identity is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := identityPolicyOption(&Identity{})
		require.Error(t, err, "an identity with neither SAN nor issuer cannot form a policy")
	})
}

// TestKeySignedBundleIdentityPolicyRejects proves the expected-identity
// binding is enforced inside the Sigstore policy: a key-signed bundle has no
// certificate, so any expected identity must fail verification rather than
// silently passing.
func TestKeySignedBundleIdentityPolicyRejects(t *testing.T) {
	t.Parallel()

	raw, pubPEM, digestHex := signTestBundle(t, []byte("content"))
	tm, err := PublicKeyMaterial([]byte(pubPEM))
	require.NoError(t, err)

	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw))

	_, err = VerifyBundle(Bundle{
		Parsed:     parsed,
		DigestAlgo: DigestAlgorithmSHA256,
		DigestHex:  digestHex,
	}, tm, &Identity{
		SignerIdentity: "dev@example.com",
		CertIssuer:     "https://accounts.example.com",
	}, verify.WithNoObserverTimestamps())
	require.Error(t, err, "an expected identity must not verify against a certificate-less bundle")
}

// TestVerifyBundleRequiresExplicitOptions guards the opts/material contract:
// passing trusted material without matching verifier options must fail
// loudly instead of silently applying public-good defaults to the wrong
// root.
func TestVerifyBundleRequiresExplicitOptions(t *testing.T) {
	t.Parallel()

	raw, pubPEM, digestHex := signTestBundle(t, []byte("content"))
	tm, err := PublicKeyMaterial([]byte(pubPEM))
	require.NoError(t, err)

	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw))

	_, err = VerifyBundle(Bundle{
		Parsed:     parsed,
		DigestAlgo: DigestAlgorithmSHA256,
		DigestHex:  digestHex,
	}, tm, nil)
	require.ErrorContains(t, err, "verifier options are required")
}

func TestDefaultVerifierOptions(t *testing.T) {
	t.Parallel()
	opts, err := DefaultVerifierOptions()
	require.NoError(t, err)
	assert.NotEmpty(t, opts)
}

func TestRetrieveBundlesUnreachableRegistry(t *testing.T) {
	t.Parallel()
	_, err := RetrieveBundles(t.Context(), "invalid.invalid/org/artifact:v1", nil)
	require.Error(t, err)
}

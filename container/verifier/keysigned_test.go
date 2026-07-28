// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushKeySignedArtifact pushes a random artifact plus a classic key-signed
// cosign signature manifest (payload layer + signature annotation at the
// sha256-<hex>.sig tag — what "cosign sign --key" produces) and returns the
// artifact ref and the signer's public key PEM.
func pushKeySignedArtifact(t *testing.T, host string) (ref string, pubPEM []byte, payload string) {
	t.Helper()

	img, err := random.Image(256, 1)
	require.NoError(t, err)
	ref = host + "/test/artifact:v1"
	parsedRef, err := name.ParseReference(ref)
	require.NoError(t, err)
	require.NoError(t, remote.Write(parsedRef, img))
	imgDigest, err := img.Digest()
	require.NoError(t, err)

	// The simple-signing payload binds the artifact manifest digest.
	payload = fmt.Sprintf(
		`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},`+
			`"type":"cosign container image signature"}}`,
		strings.SplitN(ref, ":", 2)[0], imgDigest.String())

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payloadDigest := sha256.Sum256([]byte(payload))
	sig, err := priv.Sign(rand.Reader, payloadDigest[:], nil)
	require.NoError(t, err)
	pubPEM, err = cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	require.NoError(t, err)

	layer := static.NewLayer([]byte(payload), types.MediaType(MediaTypeCosignSimpleSigningV1JSON))
	sigImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
		},
		MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
	})
	require.NoError(t, err)
	sigImg = mutate.MediaType(sigImg, types.OCIManifestSchema1)

	sigTag := parsedRef.Context().Tag(fmt.Sprint(imgDigest.Algorithm, "-", imgDigest.Hex, ".sig"))
	require.NoError(t, remote.Write(sigTag, sigImg))
	return ref, pubPEM, payload
}

// TestRetrieveKeySignedBundleRoundTrip proves the classic key-signed cosign
// layout — signature annotation, no certificate, no tlog entry — is
// retrievable and verifies against the signing key.
func TestRetrieveKeySignedBundleRoundTrip(t *testing.T) {
	t.Parallel()

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	ref, pubPEM, payload := pushKeySignedArtifact(t, host)

	bundles, err := RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err, "a key-signed signature manifest must be retrievable")
	require.Len(t, bundles, 1)
	assert.NotEmpty(t, bundles[0].Raw)
	assert.False(t, bundles[0].HasCertificate(), "the key-signed layout carries no certificate")

	// The bundle's digest must bind the simple-signing payload — that is
	// what the signature covers, per the cosign convention.
	payloadDigest := sha256.Sum256([]byte(payload))
	assert.Equal(t, hex.EncodeToString(payloadDigest[:]), bundles[0].DigestHex,
		"the bundle digest must be the simple-signing payload digest")

	_, err = VerifyBundleWithKey(bundles[0], pubPEM)
	require.NoError(t, err, "the reconstructed bundle must verify against the signing key")

	// The stored Raw form re-verifies offline with the key.
	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, DigestAlgorithmSHA256+":"+bundles[0].DigestHex, pubPEM)
	require.NoError(t, err, "the stored bundle must re-verify offline with the key")

	// A different key must not verify it.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherPub, err := cryptoutils.MarshalPublicKeyToPEM(otherPriv.Public())
	require.NoError(t, err)
	_, err = VerifyBundleWithKey(bundles[0], otherPub)
	require.ErrorIs(t, err, ErrVerificationFailed)
	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, DigestAlgorithmSHA256+":"+bundles[0].DigestHex, otherPub)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

// TestKeySignedBundleFailsKeylessVerification ensures a reconstructed
// key-signed bundle is not silently trusted by the keyless (Fulcio) path.
func TestKeySignedBundleFailsKeylessVerification(t *testing.T) {
	t.Parallel()

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	ref, _, _ := pushKeySignedArtifact(t, host)
	bundles, err := RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	tm, err := OfflineTrustedMaterial()
	require.NoError(t, err)
	opts, err := DefaultVerifierOptions()
	require.NoError(t, err)
	_, err = VerifyBundle(bundles[0], tm, nil, opts...)
	assert.ErrorIs(t, err, ErrVerificationFailed,
		"a certificate-less bundle must not pass keyless verification")
}

// TestCorruptCertificateIsNotReclassifiedAsKeySigned guards the layout
// classification: a layer whose certificate annotation is present but
// malformed is a broken keyless signature and must stay a retrieval
// failure — not silently become a "key-signed" bundle.
func TestCorruptCertificateIsNotReclassifiedAsKeySigned(t *testing.T) {
	t.Parallel()

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	img, err := random.Image(256, 1)
	require.NoError(t, err)
	ref := host + "/test/corrupt:v1"
	parsedRef, err := name.ParseReference(ref)
	require.NoError(t, err)
	require.NoError(t, remote.Write(parsedRef, img))
	imgDigest, err := img.Digest()
	require.NoError(t, err)

	layer := static.NewLayer([]byte(`{"critical":{}}`), types.MediaType(MediaTypeCosignSimpleSigningV1JSON))
	sigImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString([]byte("sig")),
			"dev.sigstore.cosign/certificate":    "not a pem certificate",
		},
		MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
	})
	require.NoError(t, err)
	sigImg = mutate.MediaType(sigImg, types.OCIManifestSchema1)
	sigTag := parsedRef.Context().Tag(fmt.Sprint(imgDigest.Algorithm, "-", imgDigest.Hex, ".sig"))
	require.NoError(t, remote.Write(sigTag, sigImg))

	_, err = RetrieveBundles(t.Context(), ref, nil)
	require.ErrorIs(t, err, ErrNoBundles,
		"a corrupt certificate must not be reclassified as a key-signed bundle")
}

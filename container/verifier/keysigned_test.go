// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

const testCosignSimpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

// pushKeySignedArtifact pushes a random artifact plus a classic key-signed
// cosign signature manifest (payload layer + signature annotation at the
// sha256-<hex>.sig tag — what "cosign sign --key" produces) and returns the
// artifact ref and the signer's public key PEM.
func pushKeySignedArtifact(t *testing.T, host string) (ref string, pubPEM []byte) {
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
	payload := fmt.Sprintf(
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

	layer := static.NewLayer([]byte(payload), types.MediaType(testCosignSimpleSigningMediaType))
	sigImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		Annotations: map[string]string{
			"dev.cosignproject.cosign/signature": base64.StdEncoding.EncodeToString(sig),
		},
		MediaType: types.MediaType(testCosignSimpleSigningMediaType),
	})
	require.NoError(t, err)
	sigImg = mutate.MediaType(sigImg, types.OCIManifestSchema1)

	h, err := v1.NewHash(imgDigest.String())
	require.NoError(t, err)
	sigTag := parsedRef.Context().Tag(fmt.Sprint(h.Algorithm, "-", h.Hex, ".sig"))
	require.NoError(t, remote.Write(sigTag, sigImg))
	return ref, pubPEM
}

// TestRetrieveKeySignedBundleRoundTrip proves the classic key-signed cosign
// layout — signature annotation, no certificate, no tlog entry — is
// retrievable and verifies against the signing key.
func TestRetrieveKeySignedBundleRoundTrip(t *testing.T) {
	t.Parallel()

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	ref, pubPEM := pushKeySignedArtifact(t, host)

	bundles, err := RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err, "a key-signed signature manifest must be retrievable")
	require.Len(t, bundles, 1)
	assert.NotEmpty(t, bundles[0].Raw)

	_, err = VerifyBundleWithKey(bundles[0], pubPEM)
	require.NoError(t, err, "the reconstructed bundle must verify against the signing key")

	// A different key must not verify it.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherPub, err := cryptoutils.MarshalPublicKeyToPEM(otherPriv.Public())
	require.NoError(t, err)
	_, err = VerifyBundleWithKey(bundles[0], otherPub)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

// TestKeySignedBundleFailsKeylessVerification ensures a reconstructed
// key-signed bundle is not silently trusted by the keyless (Fulcio) path.
func TestKeySignedBundleFailsKeylessVerification(t *testing.T) {
	t.Parallel()

	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	ref, _ := pushKeySignedArtifact(t, host)
	bundles, err := RetrieveBundles(t.Context(), ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	tm, err := OfflineTrustedMaterial()
	require.NoError(t, err)
	opts, err := DefaultVerifierOptions()
	require.NoError(t, err)
	_, err = VerifyBundle(bundles[0], tm, nil, opts...)
	require.Error(t, err, "a certificate-less bundle must not pass keyless verification")
}

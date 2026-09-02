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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingRegistry starts an in-process OCI registry that tallies blob GETs
// per digest, so a test can assert how much work a verification actually
// caused rather than only what it concluded.
func countingRegistry(t *testing.T) (host string, blobGets func(digest string) int64) {
	t.Helper()

	var mu sync.Mutex
	counts := map[string]int64{}
	inner := registry.New()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if _, digest, ok := strings.Cut(r.URL.Path, "/blobs/"); ok {
				mu.Lock()
				counts[digest]++
				mu.Unlock()
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(reg.Close)

	return strings.TrimPrefix(reg.URL, "http://"), func(digest string) int64 {
		mu.Lock()
		defer mu.Unlock()
		return counts[digest]
	}
}

// attachSignaturesSharingPayload attaches a cosign signature manifest whose
// layers all point at the SAME simple-signing payload blob but carry
// different signatures — the shape produced when several keys sign one
// artifact, since the payload is derived from the artifact and the signature
// from the key. It returns each signer's public key PEM, in layer order.
func attachSignaturesSharingPayload(t *testing.T, tag name.Tag, payload string, n int) [][]byte {
	t.Helper()

	payloadDigest := sha256.Sum256([]byte(payload))
	layer := static.NewLayer([]byte(payload), types.MediaType(MediaTypeCosignSimpleSigningV1JSON))

	sigImg := empty.Image
	pubPEMs := make([][]byte, 0, n)
	for range n {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		sig, err := priv.Sign(rand.Reader, payloadDigest[:], nil)
		require.NoError(t, err)
		pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
		require.NoError(t, err)

		sigImg, err = mutate.Append(sigImg, mutate.Addendum{
			Layer: layer,
			Annotations: map[string]string{
				annotationCosignSignature: base64.StdEncoding.EncodeToString(sig),
			},
			MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
		})
		require.NoError(t, err)
		pubPEMs = append(pubPEMs, pubPEM)
	}
	sigImg = mutate.MediaType(sigImg, types.OCIManifestSchema1)
	require.NoError(t, remote.Write(tag, sigImg))
	return pubPEMs
}

// TestRetrieveBundlesFetchesEachPayloadBlobOnce pins the deduplication: the
// layer list is registry-supplied, so fetching a blob per layer lets whoever
// serves the signature manifest multiply one verification into as many
// authenticated requests as they list layers. Distinct signatures must still
// all come back — they are what a multi-signer artifact looks like.
func TestRetrieveBundlesFetchesEachPayloadBlobOnce(t *testing.T) {
	t.Parallel()

	host, blobGets := countingRegistry(t)
	parsed, d := pushArtifact(t, host, "test/multisigned")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	pubPEMs := attachSignaturesSharingPayload(t, sigTag(parsed, d), payload, 4)

	bundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err)
	require.Len(t, bundles, 4, "every distinct signature over the artifact must be returned")

	for i, pub := range pubPEMs {
		_, err := VerifyBundleWithKey(bundles[i], pub)
		require.NoError(t, err, "signature %d must verify against its own key", i)
		assert.Equal(t, d.Hex, bundles[i].DigestHex)
	}

	sum := sha256.Sum256([]byte(payload))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	assert.Equal(t, int64(1), blobGets(digest),
		"four layers naming one payload blob must cause one fetch, not four")
}

// TestRetrieveBundlesCapsSignatureLayers pins the layer cap. A signature
// manifest can name arbitrarily many layers; processing all of them turns one
// verification into unbounded registry traffic.
func TestRetrieveBundlesCapsSignatureLayers(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/padded")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	pubPEMs := attachSignaturesSharingPayload(t, sigTag(parsed, d), payload, maxSimpleSigningLayers+8)

	bundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err, "padding must not break verification of the genuine signatures")
	require.Len(t, bundles, maxSimpleSigningLayers, "layers past the cap must be ignored")

	// The ones that were processed are the real thing, not truncated stubs.
	_, err = VerifyBundleWithKey(bundles[0], pubPEMs[0])
	require.NoError(t, err)
}

// TestFetchSimpleSigningPayloadRefusesExhaustedBudget covers the aggregate
// byte cap's boundary: once a manifest's share is spent, further blobs are
// refused rather than read.
func TestFetchSimpleSigningPayloadRefusesExhaustedBudget(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/budget")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	attachKeySignature(t, sigTag(parsed, d), payload)

	layers, err := getSimpleSigningLayersFromSignatureManifest(
		t.Context(), sigTag(parsed, d).Name(), nil)
	require.NoError(t, err)
	require.Len(t, layers, 1)

	_, err = fetchSimpleSigningPayload(t.Context(), parsed.Context(), layers[0], nil, 0)
	require.ErrorContains(t, err, "budget")

	// A budget too small to hold the blob truncates the read, which the
	// descriptor-digest check catches — the payload is never half-parsed.
	_, err = fetchSimpleSigningPayload(t.Context(), parsed.Context(), layers[0], nil, 4)
	require.ErrorContains(t, err, "does not match its descriptor digest")

	got, err := fetchSimpleSigningPayload(
		t.Context(), parsed.Context(), layers[0], nil, maxSimpleSigningPayloadTotalBytes)
	require.NoError(t, err)
	assert.Equal(t, payload, string(got))
}

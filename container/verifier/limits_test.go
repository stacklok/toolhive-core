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
	v1 "github.com/google/go-containerregistry/pkg/v1"
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

// attachSignaturesWithDistinctPayloads attaches one signature layer per
// payload and returns each signer's key and each payload descriptor digest in
// layer order. The payloads may differ in insignificant JSON whitespace while
// still binding the same artifact; distinct digests let tests fail one blob
// retrieval without affecting the others.
func attachSignaturesWithDistinctPayloads(
	t *testing.T, tag name.Tag, payloads ...string,
) ([][]byte, []v1.Hash) {
	t.Helper()

	sigImg := empty.Image
	pubPEMs := make([][]byte, 0, len(payloads))
	digests := make([]v1.Hash, 0, len(payloads))
	for _, payload := range payloads {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		payloadDigest := sha256.Sum256([]byte(payload))
		sig, err := priv.Sign(rand.Reader, payloadDigest[:], nil)
		require.NoError(t, err)
		pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
		require.NoError(t, err)

		layer := static.NewLayer([]byte(payload), types.MediaType(MediaTypeCosignSimpleSigningV1JSON))
		digest, err := layer.Digest()
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
		digests = append(digests, digest)
	}
	sigImg = mutate.MediaType(sigImg, types.OCIManifestSchema1)
	require.NoError(t, remote.Write(tag, sigImg))
	return pubPEMs, digests
}

// blobFailingRegistry starts an in-process OCI registry whose selected blob
// GET returns an operational failure. Uploads are unaffected, so callers can
// publish a valid signature manifest before choosing which descriptor will
// fail during retrieval.
func blobFailingRegistry(t *testing.T) (host string, failBlob func(v1.Hash)) {
	t.Helper()

	var mu sync.RWMutex
	var failedDigest string
	inner := registry.New()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		fail := failedDigest
		mu.RUnlock()
		if r.Method == http.MethodGet && fail != "" && strings.HasSuffix(r.URL.Path, "/blobs/"+fail) {
			http.Error(w, "injected blob failure", http.StatusServiceUnavailable)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(reg.Close)

	return strings.TrimPrefix(reg.URL, "http://"), func(digest v1.Hash) {
		mu.Lock()
		failedDigest = digest.String()
		mu.Unlock()
	}
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

// TestRetrieveBundlesStrictCompleteness covers both sides of the strict API's
// completeness contract. It must return every bundle at and below the work
// cap, fail closed above it, and preserve RetrieveBundles' existing capped,
// best-effort behavior for compatibility. The blob GET counts also pin that
// strict mode checks the layer count before doing capped work.
func TestRetrieveBundlesStrictCompleteness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		layers     int
		strictGets int64
		strictErr  bool
	}{
		{name: "single layer", layers: 1, strictGets: 1},
		{name: "at layer cap", layers: maxSimpleSigningLayers, strictGets: 1},
		{name: "above layer cap", layers: maxSimpleSigningLayers + 1, strictErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			host, blobGets := countingRegistry(t)
			parsed, d := pushArtifact(t, host, "test/strict-"+strings.ReplaceAll(tc.name, " ", "-"))
			payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
			pubPEMs := attachSignaturesSharingPayload(t, sigTag(parsed, d), payload, tc.layers)
			payloadDigest := sha256.Sum256([]byte(payload))
			blobDigest := "sha256:" + hex.EncodeToString(payloadDigest[:])

			strictBundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
			if tc.strictErr {
				require.ErrorIs(t, err, ErrBundleSetIncomplete)
				assert.Empty(t, strictBundles, "strict retrieval must not expose a partial bundle set")
			} else {
				require.NoError(t, err)
				require.Len(t, strictBundles, tc.layers)
				for i, b := range strictBundles {
					_, err = VerifyBundleWithKey(b, pubPEMs[i])
					require.NoError(t, err, "strict bundle %d must verify against its signer", i)
				}
			}
			assert.Equal(t, tc.strictGets, blobGets(blobDigest),
				"strict retrieval must retain the signature-layer work cap")

			legacyBundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
			require.NoError(t, err, "legacy retrieval must retain best-effort behavior")
			require.Len(t, legacyBundles, min(tc.layers, maxSimpleSigningLayers))
			assert.Equal(t, tc.strictGets+1, blobGets(blobDigest),
				"legacy retrieval should fetch the shared payload once")
		})
	}
}

// TestRetrieveBundlesStrictRejectsPartialLayerFetch proves that an operational
// failure for one valid signature layer is not silently converted into a
// complete negative-verification input. RetrieveBundles keeps its historical
// usable subset; RetrieveBundlesStrict refuses to return that subset as
// complete.
func TestRetrieveBundlesStrictRejectsPartialLayerFetch(t *testing.T) {
	t.Parallel()

	host, failBlob := blobFailingRegistry(t)
	parsed, d := pushArtifact(t, host, "test/strict-partial-fetch")
	basePayload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	pubPEMs, digests := attachSignaturesWithDistinctPayloads(
		t,
		sigTag(parsed, d),
		basePayload,
		basePayload+"\n",
	)
	failBlob(digests[1])

	legacyBundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err, "legacy retrieval must keep a usable bundle when a sibling fetch fails")
	require.Len(t, legacyBundles, 1)
	_, err = VerifyBundleWithKey(legacyBundles[0], pubPEMs[0])
	require.NoError(t, err)

	strictBundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, strictBundles, "strict retrieval must not expose the usable but incomplete subset")
}

// TestPoCRetrieveBundlesCapHidesValidPinnedKeySignature demonstrates that a
// negative key verdict over RetrieveBundles' result is not a verdict over all
// signatures attached to the artifact. The supplied/new key is visible in the
// processed prefix, while a valid pinned/old-key signature is just past the
// layer cap.
func TestPoCRetrieveBundlesCapHidesValidPinnedKeySignature(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/hidden-pinned-key")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	signatureTag := sigTag(parsed, d)

	// Layer zero is the explicitly supplied new key. The pinned old key is
	// attached at the first position RetrieveBundles deliberately ignores.
	pubPEMs := attachSignaturesSharingPayload(
		t, signatureTag, payload, maxSimpleSigningLayers+1)
	newKey := pubPEMs[0]
	oldKey := pubPEMs[maxSimpleSigningLayers]

	attached, err := getSimpleSigningLayersFromSignatureManifest(
		t.Context(), signatureTag.Name(), nil)
	require.NoError(t, err)
	require.Len(t, attached, maxSimpleSigningLayers+1)

	returned, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err)
	require.Len(t, returned, maxSimpleSigningLayers)

	_, err = VerifyBundleWithKey(returned[0], newKey)
	require.NoError(t, err, "the supplied new key must verify a returned bundle")
	for _, b := range returned {
		_, err = VerifyBundleWithKey(b, oldKey)
		require.ErrorIs(t, err, ErrVerificationFailed,
			"the returned set must look conclusively invalid under the old key")
	}

	strictReturned, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete,
		"strict retrieval must make the hidden-signature ambiguity explicit")
	assert.Empty(t, strictReturned)

	// Re-publish the exact ignored descriptor as the only signature layer. It
	// now survives retrieval and proves that the old-key signature attached
	// above was cryptographically valid, not malformed padding.
	oldOnly, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: static.NewLayer(
			[]byte(payload), types.MediaType(MediaTypeCosignSimpleSigningV1JSON)),
		Annotations: attached[maxSimpleSigningLayers].Annotations,
		MediaType:   types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
	})
	require.NoError(t, err)
	oldOnly = mutate.MediaType(oldOnly, types.OCIManifestSchema1)
	require.NoError(t, remote.Write(signatureTag, oldOnly))

	oldReturned, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err)
	require.Len(t, oldReturned, 1)
	_, err = VerifyBundleWithKey(oldReturned[0], oldKey)
	require.NoError(t, err,
		"the signature hidden at layer 33 must verify once it is not truncated")

	t.Logf("attached=%d returned=%d new-key=accepted old-key-over-returned=rejected old-layer-valid=true",
		len(attached), len(returned))
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

	_, err = fetchSimpleSigningPayload(t.Context(), parsed.Context(), layers[0], nil, 0, false)
	require.ErrorContains(t, err, "budget")

	// A budget too small to hold the blob truncates the read, which the
	// descriptor-digest check catches — the payload is never half-parsed.
	_, err = fetchSimpleSigningPayload(t.Context(), parsed.Context(), layers[0], nil, 4, false)
	require.ErrorContains(t, err, "does not match its descriptor digest")

	got, err := fetchSimpleSigningPayload(
		t.Context(), parsed.Context(), layers[0], nil, maxSimpleSigningPayloadTotalBytes, false)
	require.NoError(t, err)
	assert.Equal(t, payload, string(got))
}

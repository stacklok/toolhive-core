// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
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

// paginatedReferrersRegistry returns an empty but successful first referrers
// page with a Link header. Other registry operations are handled normally so
// tests can attach usable cosign material to the same artifact.
func paginatedReferrersRegistry(t *testing.T) string {
	t.Helper()

	firstPage, err := json.Marshal(v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{},
	})
	require.NoError(t, err)

	inner := registry.New()
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/") {
			w.Header().Set("Content-Type", string(types.OCIImageIndex))
			w.Header().Set("Link", `</v2/test/referrers/next>; rel="next"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(firstPage)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(reg.Close)
	return strings.TrimPrefix(reg.URL, "http://")
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

// TestRetrieveBundlesStrictAttestationRoundTrip is the positive strict-path
// counterpart to the fail-closed referrer tests below. A normal one-layer
// Sigstore referrer is a complete bounded set and must remain retrievable and
// cryptographically verifiable.
func TestRetrieveBundlesStrictAttestationRoundTrip(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/strict-attested")
	pubPEM := attachAttestationReferrer(t, parsed, d)

	bundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	assert.Equal(t, d.Hex, bundles[0].DigestHex)
	assert.Empty(t, bundles[0].SimpleSigningPayload)
	_, err = VerifyBundleWithKey(bundles[0], pubPEM)
	require.NoError(t, err)
	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, d.String(), pubPEM)
	require.NoError(t, err)
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

// TestRetrieveBundlesStrictRejectsPaginatedReferrers guards against treating
// the first page as the complete signer set. A valid cosign signature cannot
// soften that ambiguity; the legacy best-effort API remains compatible.
func TestRetrieveBundlesStrictRejectsPaginatedReferrers(t *testing.T) {
	t.Parallel()

	host := paginatedReferrersRegistry(t)
	parsed, d := pushArtifact(t, host, "test/paginated-referrers")
	pubPEM := attachKeySignature(t, sigTag(parsed, d), simpleSigningPayloadFor(parsed.Context().Name(), d))

	strictBundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, strictBundles, "strict retrieval must not expose cosign material beside an incomplete layout")

	legacyBundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err, "legacy retrieval must retain its best-effort behavior")
	require.Len(t, legacyBundles, 1)
	_, err = VerifyBundleWithKey(legacyBundles[0], pubPEM)
	require.NoError(t, err)
}

// TestRetrieveBundlesStrictRejectsMultiLayerReferrer pins the referrer shape
// invariant. Reading only layer zero would make later bundle material
// invisible, so strict retrieval must return neither it nor any partial
// result; legacy retrieval continues to use its historical first layer.
func TestRetrieveBundlesStrictRejectsMultiLayerReferrer(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/multi-layer-referrer")
	rawBundle, _, _ := signTestBundle(t, []byte("first layer bundle"))

	refImg := empty.Image
	for _, content := range [][]byte{rawBundle, []byte("second potentially relevant layer")} {
		var err error
		refImg, err = mutate.Append(refImg, mutate.Addendum{
			Layer:     static.NewLayer(content, types.MediaType(MediaTypeSigstoreBundleV03JSON)),
			MediaType: types.MediaType(MediaTypeSigstoreBundleV03JSON),
		})
		require.NoError(t, err)
	}
	refImg = mutate.MediaType(refImg, types.OCIManifestSchema1)
	refImg = mutate.ConfigMediaType(refImg, types.MediaType(MediaTypeSigstoreBundleV03JSON))
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: refImg})
	require.NoError(t, remote.WriteIndex(referrersTag(parsed.Context(), d), index))

	strictBundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, strictBundles, "strict retrieval must not expose layer zero as a complete bundle set")

	legacyBundles, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.NoError(t, err, "legacy retrieval must retain its first-layer behavior")
	require.Len(t, legacyBundles, 1)
}

// TestRetrieveBundlesStrictRejectsLyingReferrerManifestSize ensures an index
// cannot evade the aggregate manifest budget by declaring a tiny size for a
// larger candidate. The child image itself is valid and retrievable; only the
// discovery descriptor's size is dishonest.
func TestRetrieveBundlesStrictRejectsLyingReferrerManifestSize(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/lying-referrer-size")
	rawBundle, _, _ := signTestBundle(t, []byte("valid referrer bundle"))
	refImg, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:     static.NewLayer(rawBundle, types.MediaType(MediaTypeSigstoreBundleV03JSON)),
		MediaType: types.MediaType(MediaTypeSigstoreBundleV03JSON),
	})
	require.NoError(t, err)
	refImg = mutate.MediaType(refImg, types.OCIManifestSchema1)
	refImg = mutate.ConfigMediaType(refImg, types.MediaType(MediaTypeSigstoreBundleV03JSON))
	actualSize, err := refImg.Size()
	require.NoError(t, err)
	require.Greater(t, actualSize, int64(1))

	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: refImg,
		Descriptor: v1.Descriptor{
			Size: 1,
		},
	})
	require.NoError(t, remote.WriteIndex(referrersTag(parsed.Context(), d), index))

	bundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, bundles, "strict retrieval must not trust a lying candidate size")
}

// TestRetrieveBundlesStrictRejectsIndexShapedReferrer ensures every relevant
// discovery descriptor is assessed as exactly one image manifest. Treating a
// nested index as an image could hide additional candidate manifests behind
// one counted descriptor.
func TestRetrieveBundlesStrictRejectsIndexShapedReferrer(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/index-shaped-referrer")
	nested := empty.Index
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add: nested,
		Descriptor: v1.Descriptor{
			ArtifactType: MediaTypeSigstoreBundleV03JSON,
		},
	})
	require.NoError(t, remote.WriteIndex(referrersTag(parsed.Context(), d), index))

	bundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, bundles, "strict retrieval must not accept an index as one referrer image")
}

// TestRetrieveBundlesStrictPreservesReferrersFallbackRedirectFailure proves a
// valid .sig bundle cannot turn a failed referrers fallback read into a
// complete subset. go-containerregistry treats every fallback-tag 404 as
// absence, so strict retrieval must fetch that tag itself and classify the
// exact failed endpoint before aggregation.
func TestRetrieveBundlesStrictPreservesReferrersFallbackRedirectFailure(t *testing.T) {
	t.Parallel()

	inner := registry.New()
	var fallbackPath string
	reg := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/referrers/"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && fallbackPath != "" && r.URL.Path == fallbackPath:
			http.Redirect(w, r, "/login", http.StatusFound)
		case r.URL.Path == "/login":
			http.NotFound(w, r)
		default:
			inner.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(reg.Close)

	host := strings.TrimPrefix(reg.URL, "http://")
	parsed, digest := pushArtifact(t, host, "test/referrers-fallback-redirect")
	attachKeySignature(t, sigTag(parsed, digest), simpleSigningPayloadFor(parsed.Context().Name(), digest))
	fallbackPath = indexManifestRequestTarget(referrersTag(parsed.Context(), digest)).path

	bundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, bundles, "strict retrieval must not expose the otherwise valid .sig subset")
	var transportErr *transport.Error
	require.ErrorAs(t, err, &transportErr)
	require.NotNil(t, transportErr.Request)
	assert.Equal(t, "/login", transportErr.Request.URL.Path)
}

// TestRetrieveBundlesStrictRejectsIndexShapedSignatureTag ensures a .sig tag
// cannot hide unassessed signatures behind an OCI index. A usable referrer is
// present to prove strict aggregation returns no partial evidence.
func TestRetrieveBundlesStrictRejectsIndexShapedSignatureTag(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, digest := pushArtifact(t, host, "test/index-shaped-signature")
	attachAttestationReferrer(t, parsed, digest)
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: empty.Image})
	require.NoError(t, remote.WriteIndex(sigTag(parsed, digest), index))

	bundles, err := RetrieveBundlesStrict(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrBundleSetIncomplete)
	assert.Empty(t, bundles, "strict retrieval must not expose the otherwise valid referrer subset")
}

// TestExtractBundleFromImageStrictReadBudget exercises the aggregate-budget
// boundary directly, avoiding a 10 MiB fixture. Strict extraction succeeds at
// the exact budget and fails closed when the caller's remaining aggregate
// allowance cannot hold the complete bundle.
func TestExtractBundleFromImageStrictReadBudget(t *testing.T) {
	t.Parallel()

	rawBundle, _, _ := signTestBundle(t, []byte("budgeted bundle"))
	tests := []struct {
		name      string
		budget    int64
		wantBytes int64
		wantErr   bool
	}{
		{name: "exact budget", budget: int64(len(rawBundle)), wantBytes: int64(len(rawBundle))},
		{name: "one byte short", budget: int64(len(rawBundle) - 1), wantBytes: int64(len(rawBundle)), wantErr: true},
		{name: "exhausted", budget: 0, wantBytes: 0, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			img, err := mutate.Append(empty.Image, mutate.Addendum{
				Layer: static.NewLayer(rawBundle, types.MediaType(MediaTypeSigstoreBundleV03JSON)),
			})
			require.NoError(t, err)
			got, bytesRead, err := extractBundleFromImage(img, true, tc.budget)
			assert.Equal(t, tc.wantBytes, bytesRead)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrBundleSetIncomplete)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, got)
		})
	}
}

// TestRetrieveBundlesStrictPreservesContextErrors ensures the completeness
// sentinel does not hide why retrieval stopped. Callers can classify both the
// strict contract and cancellation/deadline through errors.Is.
func TestRetrieveBundlesStrictPreservesContextErrors(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, _ := pushArtifact(t, host, "test/strict-context")
	tests := []struct {
		name    string
		newCtx  func(context.Context) (context.Context, context.CancelFunc)
		wantErr error
	}{
		{
			name: "canceled",
			newCtx: func(parent context.Context) (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(parent)
				cancel()
				return ctx, cancel
			},
			wantErr: context.Canceled,
		},
		{
			name: "deadline exceeded",
			newCtx: func(parent context.Context) (context.Context, context.CancelFunc) {
				return context.WithDeadline(parent, time.Now().Add(-time.Second))
			},
			wantErr: context.DeadlineExceeded,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := tc.newCtx(t.Context())
			defer cancel()
			bundles, err := RetrieveBundlesStrict(ctx, parsed.Name(), nil)
			require.ErrorIs(t, err, ErrBundleSetIncomplete)
			require.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, bundles)
		})
	}
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

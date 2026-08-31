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

// keySignedArtifact is a pushed artifact plus the key-signed cosign
// signature attached to it.
type keySignedArtifact struct {
	// ref is the artifact reference, tag-qualified.
	ref string
	// parsed is ref, parsed.
	parsed name.Reference
	// digest is the artifact's own manifest digest.
	digest v1.Hash
	// pubPEM is the signing key's public half.
	pubPEM []byte
	// payload is the simple-signing payload the signature covers.
	payload string
}

// artifactDigest returns the artifact's manifest digest in the
// "<algorithm>:<hex>" form the verifier's offline entry points take.
func (a keySignedArtifact) artifactDigest() string {
	return a.digest.String()
}

// sigTag returns the mutable cosign signature tag for the artifact.
func sigTag(ref name.Reference, d v1.Hash) name.Tag {
	return ref.Context().Tag(fmt.Sprint(d.Algorithm, "-", d.Hex, ".sig"))
}

// pushArtifact pushes a random artifact at host/repoPath:v1.
func pushArtifact(t *testing.T, host, repoPath string) (name.Reference, v1.Hash) {
	t.Helper()

	img, err := random.Image(256, 1)
	require.NoError(t, err)
	parsed, err := name.ParseReference(host + "/" + repoPath + ":v1")
	require.NoError(t, err)
	require.NoError(t, remote.Write(parsed, img))
	d, err := img.Digest()
	require.NoError(t, err)
	return parsed, d
}

// simpleSigningPayloadFor builds a well-formed cosign simple-signing payload
// binding the artifact at repo pinned to d — the payload a genuine signer
// produces.
func simpleSigningPayloadFor(repo string, d v1.Hash) string {
	return fmt.Sprintf(
		`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},`+
			`"type":%q}}`,
		repo, d.String(), CosignSignatureType)
}

// attachKeySignature signs payload with a fresh key pair and attaches the
// result as a classic key-signed cosign signature manifest (payload layer
// plus signature annotation at the sha256-<hex>.sig tag — what "cosign sign
// --key" produces). It returns the signer's public key PEM.
func attachKeySignature(t *testing.T, tag name.Tag, payload string) []byte {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	payloadDigest := sha256.Sum256([]byte(payload))
	sig, err := priv.Sign(rand.Reader, payloadDigest[:], nil)
	require.NoError(t, err)
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
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
	require.NoError(t, remote.Write(tag, sigImg))
	return pubPEM
}

// pushKeySignedArtifact pushes a random artifact plus a genuine key-signed
// cosign signature over it.
func pushKeySignedArtifact(t *testing.T, host, repoPath string) keySignedArtifact {
	t.Helper()

	parsed, d := pushArtifact(t, host, repoPath)
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	pubPEM := attachKeySignature(t, sigTag(parsed, d), payload)
	return keySignedArtifact{
		ref:     parsed.Name(),
		parsed:  parsed,
		digest:  d,
		pubPEM:  pubPEM,
		payload: payload,
	}
}

// newTestRegistry starts an in-process OCI registry and returns its host.
func newTestRegistry(t *testing.T) string {
	t.Helper()
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	return strings.TrimPrefix(reg.URL, "http://")
}

// TestRetrieveKeySignedBundleRoundTrip proves the classic key-signed cosign
// layout — signature annotation, no certificate, no tlog entry — is
// retrievable and verifies against the signing key.
func TestRetrieveKeySignedBundleRoundTrip(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	art := pushKeySignedArtifact(t, host, "test/artifact")

	bundles, err := RetrieveBundles(t.Context(), art.ref, nil)
	require.NoError(t, err, "a key-signed signature manifest must be retrievable")
	require.Len(t, bundles, 1)
	assert.NotEmpty(t, bundles[0].Raw)
	assert.False(t, bundles[0].HasCertificate(), "the key-signed layout carries no certificate")

	// The bundle binds the ARTIFACT digest, not the digest of the payload
	// blob the signature happens to cover. Those differ for this layout, and
	// the artifact digest is the one a caller has and can act on; the
	// payload is carried alongside so the package can still check the
	// signature against what it actually signs.
	assert.Equal(t, art.digest.Hex, bundles[0].DigestHex,
		"the bundle digest must be the artifact manifest digest")
	assert.Equal(t, DigestAlgorithmSHA256, bundles[0].DigestAlgo)
	assert.Equal(t, art.payload, string(bundles[0].SimpleSigningPayload),
		"the simple-signing payload must be carried with the bundle")

	_, err = VerifyBundleWithKey(bundles[0], art.pubPEM)
	require.NoError(t, err, "the reconstructed bundle must verify against the signing key")

	// The stored Raw form re-verifies offline against the artifact digest —
	// the value a caller naturally holds, with no payload digest involved.
	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, art.artifactDigest(), art.pubPEM)
	require.NoError(t, err, "the stored bundle must re-verify offline against the artifact digest")

	// A different key must not verify it.
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherPub, err := cryptoutils.MarshalPublicKeyToPEM(otherPriv.Public())
	require.NoError(t, err)
	_, err = VerifyBundleWithKey(bundles[0], otherPub)
	require.ErrorIs(t, err, ErrVerificationFailed)
	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, art.artifactDigest(), otherPub)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

// TestVerifyBundleOfflineRejectsWrongArtifactDigest is the other half of the
// offline contract: a stored bundle must not verify against an artifact it
// does not cover. Without the payload binding this is exactly the check that
// silently passes — the stored bundle is internally consistent no matter
// which artifact digest it is handed.
func TestVerifyBundleOfflineRejectsWrongArtifactDigest(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	art := pushKeySignedArtifact(t, host, "test/artifact")
	_, otherDigest := pushArtifact(t, host, "test/other")

	bundles, err := RetrieveBundles(t.Context(), art.ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	_, err = VerifyBundleOfflineWithKey(bundles[0].Raw, otherDigest.String(), art.pubPEM)
	require.ErrorIs(t, err, ErrSignatureArtifactMismatch,
		"a stored bundle must not verify against an artifact its payload does not name")
}

// TestRetrieveBundlesRejectsCrossArtifactSignature is the regression test for
// signature-to-artifact binding. A signature manifest is a plain OCI
// manifest at a mutable "sha256-<hex>.sig" tag, so anyone who can write tags
// in a repository can point an artifact's tag at a genuine signature
// manifest belonging to a different artifact. Everything about that
// signature verifies — the certificate or key, the transparency log, the
// signature over its payload — because it IS genuine. The only thing that
// distinguishes it is the artifact its payload names.
func TestRetrieveBundlesRejectsCrossArtifactSignature(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)

	// A: an artifact with a genuine key-signed cosign signature.
	signed := pushKeySignedArtifact(t, host, "test/signed")

	// B: an unrelated artifact nobody signed, in a repository the attacker
	// controls.
	victim, victimDigest := pushArtifact(t, host, "test/unsigned")

	// Copy A's signature manifest, verbatim, onto B's signature tag.
	stolen, err := remote.Image(sigTag(signed.parsed, signed.digest))
	require.NoError(t, err)
	require.NoError(t, remote.Write(sigTag(victim, victimDigest), stolen))

	_, err = RetrieveBundles(t.Context(), victim.Name(), nil)
	require.Error(t, err, "a signature for another artifact must not make this one signed")
	assert.ErrorIs(t, err, ErrSignatureArtifactMismatch,
		"the verdict must say the signature does not cover this artifact")
	assert.NotErrorIs(t, err, ErrNoBundles,
		"a substituted signature is a distinct verdict from an absent one")

	// The same substitution must not slip through the Sigstore.VerifyServer
	// path either, which reports unsigned artifacts as ErrImageNotSigned.
	s := &Sigstore{}
	_, err = s.GetVerificationResults(victim.Name())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSignatureArtifactMismatch)

	// And A itself still verifies: the check rejects the substitution, not
	// the signature.
	bundles, err := RetrieveBundles(t.Context(), signed.ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	_, err = VerifyBundleWithKey(bundles[0], signed.pubPEM)
	require.NoError(t, err)
}

// TestRetrieveBundlesRejectsWrongPayloadType covers the other half of the
// payload check: critical.type identifies the payload as a container image
// signature. A payload of some other type may be perfectly well signed
// without being a statement about this artifact at all.
func TestRetrieveBundlesRejectsWrongPayloadType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		payload func(repo string, d v1.Hash) string
	}{
		{
			name: "wrong critical type",
			payload: func(repo string, d v1.Hash) string {
				return fmt.Sprintf(
					`{"critical":{"identity":{"docker-reference":%q},`+
						`"image":{"docker-manifest-digest":%q},"type":"some other signature"}}`,
					repo, d.String())
			},
		},
		{
			name: "missing critical type",
			payload: func(repo string, d v1.Hash) string {
				return fmt.Sprintf(
					`{"critical":{"identity":{"docker-reference":%q},`+
						`"image":{"docker-manifest-digest":%q}}}`,
					repo, d.String())
			},
		},
		{
			name: "missing manifest digest",
			payload: func(repo string, _ v1.Hash) string {
				return fmt.Sprintf(
					`{"critical":{"identity":{"docker-reference":%q},"image":{},"type":%q}}`,
					repo, CosignSignatureType)
			},
		},
		{
			name: "manifest digest without algorithm",
			payload: func(repo string, d v1.Hash) string {
				return fmt.Sprintf(
					`{"critical":{"identity":{"docker-reference":%q},`+
						`"image":{"docker-manifest-digest":%q},"type":%q}}`,
					repo, d.Hex, CosignSignatureType)
			},
		},
		{
			name:    "payload is not json",
			payload: func(string, v1.Hash) string { return "not a payload" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			host := newTestRegistry(t)
			parsed, d := pushArtifact(t, host, "test/artifact")
			attachKeySignature(t, sigTag(parsed, d), tc.payload(parsed.Context().Name(), d))

			_, err := RetrieveBundles(t.Context(), parsed.Name(), nil)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSignatureArtifactMismatch)
			assert.NotErrorIs(t, err, ErrNoBundles)
		})
	}
}

// TestKeySignedBundleFailsKeylessVerification ensures a reconstructed
// key-signed bundle is not silently trusted by the keyless (Fulcio) path.
func TestKeySignedBundleFailsKeylessVerification(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	art := pushKeySignedArtifact(t, host, "test/artifact")

	bundles, err := RetrieveBundles(t.Context(), art.ref, nil)
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
//
// The payload here binds the artifact correctly, so the only reason the
// layer can be rejected is the certificate: otherwise the payload check
// would mask what this test is about.
func TestCorruptCertificateIsNotReclassifiedAsKeySigned(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/corrupt")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)

	layer := static.NewLayer([]byte(payload), types.MediaType(MediaTypeCosignSimpleSigningV1JSON))
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
	require.NoError(t, remote.Write(sigTag(parsed, d), sigImg))

	_, err = RetrieveBundles(t.Context(), parsed.Name(), nil)
	require.ErrorIs(t, err, ErrNoBundles,
		"a corrupt certificate must not be reclassified as a key-signed bundle")
}

// TestFetchSimpleSigningPayloadRejectsTamperedBlob covers the descriptor
// digest check on the payload blob. The blob is what the signature is
// verified against, so a blob that does not hash to the digest the manifest
// claims must not be used — a registry that serves different bytes than the
// descriptor names would otherwise decide what "the payload" is.
func TestFetchSimpleSigningPayloadRejectsTamperedBlob(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	parsed, d := pushArtifact(t, host, "test/artifact")
	payload := simpleSigningPayloadFor(parsed.Context().Name(), d)
	attachKeySignature(t, sigTag(parsed, d), payload)

	// A descriptor naming a digest whose blob was never pushed: the fetch
	// must fail rather than fall back to whatever the registry returns.
	bogus := sha256.Sum256([]byte("a blob nobody pushed"))
	_, err := fetchSimpleSigningPayload(t.Context(), parsed.Context(), v1.Descriptor{
		MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
		Digest:    v1.Hash{Algorithm: DigestAlgorithmSHA256, Hex: hex.EncodeToString(bogus[:])},
	}, nil)
	require.Error(t, err)

	// An unsupported digest algorithm is refused before any network call:
	// the payload digest feeds the signature check, which is SHA-256 only.
	_, err = fetchSimpleSigningPayload(t.Context(), parsed.Context(), v1.Descriptor{
		MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON),
		Digest:    v1.Hash{Algorithm: "sha512", Hex: strings.Repeat("ab", 64)},
	}, nil)
	require.ErrorContains(t, err, "unsupported simple signing layer digest algorithm")
}

// TestLegacyStoredBundleWithoutPayloadFailsClosed documents the migration
// behaviour for bundles persisted before the payload travelled with them. A
// bare Sigstore bundle reconstructed from a cosign signature carries no way
// to tell which artifact it covers, so binding it to the artifact digest
// cannot succeed — and must not appear to. Consumers holding such bundles
// re-retrieve them; the failure is closed, not silent.
func TestLegacyStoredBundleWithoutPayloadFailsClosed(t *testing.T) {
	t.Parallel()

	host := newTestRegistry(t)
	art := pushKeySignedArtifact(t, host, "test/artifact")

	bundles, err := RetrieveBundles(t.Context(), art.ref, nil)
	require.NoError(t, err)
	require.Len(t, bundles, 1)

	// What an older version would have stored: the bundle alone.
	legacyRaw, err := bundles[0].Parsed.MarshalJSON()
	require.NoError(t, err)

	_, err = VerifyBundleOfflineWithKey(legacyRaw, art.artifactDigest(), art.pubPEM)
	require.ErrorIs(t, err, ErrVerificationFailed,
		"a stored bundle with no payload cannot be bound to an artifact and must fail")
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/secure-systems-lab/go-securesystemslib/encrypted"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/container/verifier"
)

// testRef is a stand-in artifact reference for cases that never reach a
// registry — input validation and payload construction.
const testRef = "example.com/org/skill:v1"

// writeTestKey generates an ECDSA P-256 key pair, writes the private key as
// a cosign-style PEM file, and returns its path plus the public key PEM.
func writeTestKey(t *testing.T) (keyPath string, pubPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	require.NoError(t, err)
	keyPath = filepath.Join(t.TempDir(), "cosign.key")
	require.NoError(t, os.WriteFile(keyPath, privPEM, 0o600))

	pubPEM, err = cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	require.NoError(t, err)
	return keyPath, pubPEM
}

// pushTestArtifact pushes a random OCI image to the in-process registry and
// returns its reference and manifest digest.
func pushTestArtifact(t *testing.T, registryHost string) (ref string, digestStr string) {
	t.Helper()
	img, err := random.Image(256, 1)
	require.NoError(t, err)
	ref = registryHost + "/test/skill:v1"
	parsed, err := name.ParseReference(ref)
	require.NoError(t, err)
	require.NoError(t, remote.Write(parsed, img))
	d, err := img.Digest()
	require.NoError(t, err)
	return ref, d.String()
}

// verifyKeyBundle verifies a signing result against the public key, through
// the sibling verifier package's real entry point.
//
// It uses res.PayloadDigest rather than recomputing a digest, which is the
// point: a consumer holding only the Result must be able to verify it. When
// this helper had to rebuild the simple-signing payload itself, the test
// passed while the public API was unusable as documented.
func verifyKeyBundle(t *testing.T, res *Result, pubPEM []byte) error {
	t.Helper()
	require.NotEmpty(t, res.PayloadDigest, "a signing result must carry the digest it signed")
	_, err := verifier.VerifyBundleOfflineWithKey(res.Bundle, res.PayloadDigest, pubPEM)
	return err
}

//nolint:paralleltest // uses t.Setenv indirectly via subtests sharing a registry
func TestSignOCIRoundTrip(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	keyPath, pubPEM := writeTestKey(t)
	ref, digestStr := pushTestArtifact(t, host)

	raw, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
	require.NoError(t, err)
	require.NotEmpty(t, raw.Bundle)

	// The returned bundle verifies against the signing key over the
	// simple-signing payload digest.
	payload, err := SimpleSigningPayload(ref, digestStr)
	require.NoError(t, err)
	payloadDigest := sha256.Sum256(payload)
	require.NoError(t, verifyKeyBundle(t, raw, pubPEM),
		"the returned bundle must verify against the signing key")

	// The attached signature manifest reconstructs to the SAME signature:
	// this is the layout toolhive-core's bundle retrieval (and cosign)
	// discover — one signature, two representations.
	h, err := v1.NewHash(digestStr)
	require.NoError(t, err)
	sigRef := host + "/test/skill:" + h.Algorithm + "-" + h.Hex + ".sig"
	manifestBytes, err := crane.Manifest(sigRef)
	require.NoError(t, err, "the signature manifest must exist at the cosign .sig tag")

	var manifest struct {
		Layers []struct {
			MediaType   string            `json:"mediaType"`
			Digest      string            `json:"digest"`
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	require.NoError(t, json.Unmarshal(manifestBytes, &manifest))
	require.Len(t, manifest.Layers, 1)
	layer := manifest.Layers[0]
	assert.Equal(t, mediaTypeCosignSimpleSigningV1JSON, layer.MediaType)

	// The layer content digest is the payload digest the bundle signed.
	wantLayerDigest := "sha256:" + hex.EncodeToString(payloadDigest[:])
	assert.Equal(t, wantLayerDigest, layer.Digest,
		"the signature manifest layer must be the exact signed payload")

	// The annotation signature matches the bundle's message signature.
	parsed := &bundle.Bundle{}
	require.NoError(t, parsed.UnmarshalJSON(raw.Bundle))
	bundleSig := parsed.Bundle.GetMessageSignature().GetSignature()
	annotationSig, err := base64.StdEncoding.DecodeString(layer.Annotations[annotationCosignSignature])
	require.NoError(t, err)
	assert.Equal(t, bundleSig, annotationSig,
		"the attached annotation and the returned bundle must carry the same signature")
}

//nolint:paralleltest // shares process env semantics with the round-trip test
func TestSignOCIRejectsWrongKeyVerification(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	keyPath, _ := writeTestKey(t)
	_, otherPub := writeTestKey(t)
	ref, digestStr := pushTestArtifact(t, host)

	raw, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
	require.NoError(t, err)

	require.Error(t, verifyKeyBundle(t, raw, otherPub),
		"a different key must not verify the bundle")
}

func TestSignOCIRequiresKey(t *testing.T) {
	t.Parallel()
	_, err := NewDefault(nil).SignOCI(t.Context(), "ghcr.io/org/skill:v1", "sha256:abc", Options{})
	require.ErrorIs(t, err, ErrKeyRequired)
}

func TestSignOCIEncryptedKey(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	// PKCS#8 standard encryption under the "ENCRYPTED SIGSTORE PRIVATE KEY"
	// label. NOT what `cosign generate-key-pair` produces — that is covered
	// by TestSignOCIAcceptsCosignCLIKeyFormat — but the same label is used
	// for both, so this path must keep working too.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encDER, err := cryptoutils.MarshalPrivateKeyToEncryptedDER(
		priv, cryptoutils.StaticPasswordFunc([]byte("test-password")))
	require.NoError(t, err)
	encPEM := pem.EncodeToMemory(&pem.Block{
		Type:  string(cryptoutils.EncryptedSigstorePrivateKeyPEMType),
		Bytes: encDER,
	})
	keyPath := filepath.Join(t.TempDir(), "cosign-enc.key")
	require.NoError(t, os.WriteFile(keyPath, encPEM, 0o600))

	ref, digestStr := pushTestArtifact(t, host)

	t.Setenv("COSIGN_PASSWORD", "test-password")
	raw, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
	require.NoError(t, err, "an encrypted key must decrypt via COSIGN_PASSWORD")
	require.NotEmpty(t, raw.Bundle)

	t.Setenv("COSIGN_PASSWORD", "wrong-password")
	_, err = NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
	require.Error(t, err, "a wrong password must fail key decryption")
}

func TestSignOCIInputErrors(t *testing.T) {
	t.Parallel()
	keyPath, _ := writeTestKey(t)

	tests := []struct {
		name    string
		key     string
		ref     string
		digest  string
		wantErr string
	}{
		{
			name:    "garbage key file",
			key:     writeGarbageKey(t),
			ref:     testRef,
			digest:  "sha256:" + strings.Repeat("a", 64),
			wantErr: "decoding signing key",
		},
		{
			name:    "invalid image reference",
			key:     keyPath,
			ref:     "NOT a valid ref!!",
			digest:  "sha256:" + strings.Repeat("a", 64),
			wantErr: "parsing image reference",
		},
		{
			name:    "empty digest",
			key:     keyPath,
			ref:     testRef,
			digest:  "",
			wantErr: "digest is required",
		},
		{
			name:    "malformed digest",
			key:     keyPath,
			ref:     testRef,
			digest:  "sha256:tooshort",
			wantErr: "parsing digest",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewDefault(nil).SignOCI(t.Context(), tc.ref, tc.digest, Options{Key: tc.key})
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func writeGarbageKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "garbage.key")
	require.NoError(t, os.WriteFile(p, []byte("not a pem key"), 0o600))
	return p
}

func TestParseManifestDigestNormalizesBareHex(t *testing.T) {
	t.Parallel()
	hexDigest := strings.Repeat("a", 64)
	d, err := parseManifestDigest(hexDigest)
	require.NoError(t, err)
	assert.Equal(t, "sha256:"+hexDigest, d.String())
}

func TestSimpleSigningPayloadBindsDigestAndRepo(t *testing.T) {
	t.Parallel()
	digestStr := "sha256:" + strings.Repeat("b", 64)
	payload, err := SimpleSigningPayload(testRef, digestStr)
	require.NoError(t, err)

	var got cosignSimpleSigning
	require.NoError(t, json.Unmarshal(payload, &got))
	assert.Equal(t, digestStr, got.Critical.Image.DockerManifestDigest)
	// The identity is the repository, not the tag — retagging must not
	// invalidate the signature's digest binding.
	assert.Equal(t, "example.com/org/skill", got.Critical.Identity.DockerReference)
	assert.Equal(t, "cosign container image signature", got.Critical.Type)
}

func TestFileKeypairMetadata(t *testing.T) {
	t.Parallel()
	keyPath, pubPEM := writeTestKey(t)
	kp, err := loadKeypair(keyPath)
	require.NoError(t, err)

	assert.Equal(t, "ecdsa", kp.GetKeyAlgorithm())
	assert.Equal(t, protocommon.HashAlgorithm_SHA2_256, kp.GetHashAlgorithm())
	assert.Equal(t, protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, kp.GetSigningAlgorithm())
	gotPEM, err := kp.GetPublicKeyPem()
	require.NoError(t, err)
	assert.Equal(t, string(pubPEM), gotPEM)
	assert.Equal(t, pubPEM, kp.GetHint())
	assert.NotNil(t, kp.GetPublicKey())
}

func TestResolveKeyPath(t *testing.T) {
	t.Parallel()

	t.Run("regular file resolves", func(t *testing.T) {
		t.Parallel()
		p := filepath.Join(t.TempDir(), "key.pem")
		require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
		resolved, err := resolveKeyPath(p)
		require.NoError(t, err)
		assert.True(t, filepath.IsAbs(resolved))
	})

	t.Run("directory rejected", func(t *testing.T) {
		t.Parallel()
		_, err := resolveKeyPath(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a regular file")
	})

	t.Run("missing file rejected", func(t *testing.T) {
		t.Parallel()
		_, err := resolveKeyPath(filepath.Join(t.TempDir(), "nope.pem"))
		require.Error(t, err)
	})

	t.Run("empty path rejected", func(t *testing.T) {
		t.Parallel()
		_, err := resolveKeyPath("")
		require.ErrorIs(t, err, ErrKeyRequired)
	})
}

// writeCosignFormatKey writes a private key in the exact format the cosign
// CLI produces: PKCS#8 sealed with scrypt + nacl/secretbox by
// go-securesystemslib, under the "ENCRYPTED SIGSTORE PRIVATE KEY" label.
//
// This differs from cryptoutils.MarshalPrivateKeyToEncryptedDER, which
// writes PKCS#8 standard encryption under the *same* label. Fixtures built
// with cryptoutils therefore look like cosign keys but are not, which is how
// `thv skill push --key` shipped unable to read any key from
// `cosign generate-key-pair` while its tests passed.
func writeCosignFormatKey(t *testing.T, password []byte) (keyPath string, pubPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	sealed, err := encrypted.Encrypt(der, password)
	require.NoError(t, err)

	keyPath = filepath.Join(t.TempDir(), "cosign.key")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED SIGSTORE PRIVATE KEY",
		Bytes: sealed,
	}), 0o600))

	pubPEM, err = cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	require.NoError(t, err)
	return keyPath, pubPEM
}

// TestSignOCIAcceptsCosignCLIKeyFormat is the regression test for the
// interop gap: a key straight from `cosign generate-key-pair` must sign, and
// the resulting bundle must verify against the matching public key.
//
//nolint:paralleltest // uses t.Setenv
func TestSignOCIAcceptsCosignCLIKeyFormat(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	for _, tc := range []struct {
		name     string
		password string
	}{
		{name: "empty password, as cosign writes by default", password: ""},
		{name: "password protected", password: "hunter2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyPath, pubPEM := writeCosignFormatKey(t, []byte(tc.password))
			ref, digestStr := pushTestArtifact(t, host)

			t.Setenv("COSIGN_PASSWORD", tc.password)
			raw, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
			require.NoError(t, err, "a key from `cosign generate-key-pair` must be usable")

			require.NoError(t, verifyKeyBundle(t, raw, pubPEM))
		})
	}
}

//nolint:paralleltest // uses t.Setenv
func TestSignOCICosignKeyWrongPasswordIsReported(t *testing.T) {
	keyPath, _ := writeCosignFormatKey(t, []byte("correct-password"))

	t.Setenv("COSIGN_PASSWORD", "wrong-password")
	_, err := NewDefault(nil).SignOCI(t.Context(), testRef,
		"sha256:"+strings.Repeat("a", 64), Options{Key: keyPath})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "COSIGN_PASSWORD",
		"a wrong password must point at the password, not surface an opaque ASN.1 error")
}

// sigLayers returns the layer descriptors of the cosign signature manifest
// attached to digestStr.
func sigLayers(t *testing.T, ref, digestStr string) []v1.Descriptor {
	t.Helper()
	parsed, err := name.ParseReference(ref)
	require.NoError(t, err)
	h, err := v1.NewHash(digestStr)
	require.NoError(t, err)
	sigTag := parsed.Context().Tag(h.Algorithm + "-" + h.Hex + ".sig")
	img, err := remote.Image(sigTag)
	require.NoError(t, err)
	m, err := img.Manifest()
	require.NoError(t, err)
	return m.Layers
}

// TestSignOCIAppendsRatherThanReplacingSignatures covers the multi-signer
// case: an artifact can legitimately carry signatures from several parties,
// and signing it again must not delete trust material belonging to someone
// else. Building the manifest from empty.Image and writing it to the .sig
// tag silently did exactly that.
//
//nolint:paralleltest // uses t.Setenv
func TestSignOCIAppendsRatherThanReplacingSignatures(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	t.Setenv("COSIGN_PASSWORD", "")
	keyA, pubA := writeTestKey(t)
	keyB, pubB := writeTestKey(t)
	ref, digestStr := pushTestArtifact(t, host)

	rawA, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyA})
	require.NoError(t, err)
	require.Len(t, sigLayers(t, ref, digestStr), 1, "first signature creates the manifest")

	rawB, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyB})
	require.NoError(t, err)

	layers := sigLayers(t, ref, digestStr)
	require.Len(t, layers, 2, "a second signer must not evict the first signature")

	// Both signatures must still verify — the manifest carries two distinct
	// annotations, one per key.
	require.NoError(t, verifyKeyBundle(t, rawA, pubA))
	require.NoError(t, verifyKeyBundle(t, rawB, pubB))

	sigs := map[string]bool{}
	for _, l := range layers {
		sigs[l.Annotations[annotationCosignSignature]] = true
	}
	assert.Len(t, sigs, 2, "the two layers must carry distinct signatures")
}

// TestSignOCIWithSameKeyIsIdempotent keeps repeated pushes from growing the
// signature manifest without bound.
//
//nolint:paralleltest // uses t.Setenv
func TestSignOCIWithSameKeyIsIdempotent(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	t.Setenv("COSIGN_PASSWORD", "")
	key, _ := writeTestKey(t)
	ref, digestStr := pushTestArtifact(t, host)

	for range 3 {
		_, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: key})
		require.NoError(t, err)
	}
	assert.Len(t, sigLayers(t, ref, digestStr), 1,
		"re-signing with the same key must not append a duplicate layer")
}

// TestResultCarriesTheDigestItSigned pins the API contract the reviewer of
// #230 flagged: the bundle signs the simple-signing payload, NOT the
// artifact digest passed to SignOCI. A consumer holding only the bundle and
// the artifact digest — which the old []byte return implied was enough —
// would pass the wrong digest to a bundle verifier and always fail.
//
//nolint:paralleltest // uses t.Setenv
func TestResultCarriesTheDigestItSigned(t *testing.T) {
	reg := httptest.NewServer(registry.New())
	t.Cleanup(reg.Close)
	host := strings.TrimPrefix(reg.URL, "http://")

	t.Setenv("COSIGN_PASSWORD", "")
	keyPath, pubPEM := writeTestKey(t)
	ref, digestStr := pushTestArtifact(t, host)

	res, err := NewDefault(nil).SignOCI(t.Context(), ref, digestStr, Options{Key: keyPath})
	require.NoError(t, err)

	assert.NotEqual(t, digestStr, res.PayloadDigest,
		"the signed digest is the payload's, not the artifact's — if these ever match, the contract changed")

	// The artifact digest must NOT verify the bundle. This is the mistake
	// the previous signature invited.
	_, err = verifier.VerifyBundleOfflineWithKey(res.Bundle, digestStr, pubPEM)
	require.Error(t, err, "the artifact digest must not verify a payload-bound bundle")

	// The digest the Result reports must.
	_, err = verifier.VerifyBundleOfflineWithKey(res.Bundle, res.PayloadDigest, pubPEM)
	require.NoError(t, err)

	// And PayloadDigest recomputes the same value from ref + digest alone,
	// which is all a later consumer has.
	recomputed, err := PayloadDigest(ref, digestStr)
	require.NoError(t, err)
	assert.Equal(t, res.PayloadDigest, recomputed)
}

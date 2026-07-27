// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// DigestAlgorithmSHA256 is the digest algorithm name used throughout the
// Sigstore bundle formats this package handles.
const DigestAlgorithmSHA256 = "sha256"

// ErrNoBundles is returned by RetrieveBundles when the artifact carries no
// Sigstore signature or attestation in any supported layout — i.e. the
// artifact is unsigned as far as this package can tell.
var ErrNoBundles = errors.New("no sigstore bundles found for artifact")

// Bundle is a Sigstore bundle retrieved for an artifact, in both parsed and
// serialized form. Raw is the canonical JSON encoding, suitable for durable
// storage and later re-verification with VerifyBundleOffline.
type Bundle struct {
	// Parsed is the decoded bundle.
	Parsed *bundle.Bundle
	// Raw is the bundle's canonical JSON serialization.
	Raw []byte
	// DigestAlgo is the algorithm of the artifact digest the bundle signs
	// (e.g. "sha256").
	DigestAlgo string
	// DigestHex is the hex-encoded artifact digest the bundle signs.
	DigestHex string
}

// Identity is the signer identity extracted from a verified Sigstore bundle.
type Identity struct {
	// SignerIdentity is the certificate's subject identity. For
	// certificates issued through GitHub Actions tokens this is the
	// workflow path relative to the repository (see
	// signerIdentityFromCertificate); otherwise it is the certificate SAN
	// verbatim (a URI, email, or SPIFFE ID).
	SignerIdentity string
	// CertIssuer is the OIDC issuer that authenticated the signer.
	CertIssuer string
	// SourceRepositoryURI is the source repository recorded in the Fulcio
	// certificate extensions, when present.
	SourceRepositoryURI string
}

// IdentityFromResult extracts the signer Identity from a verification result.
func IdentityFromResult(r *verify.VerificationResult) (*Identity, error) {
	if r == nil || r.Signature == nil || r.Signature.Certificate == nil {
		return nil, errors.New("verification result carries no certificate summary")
	}
	signer, err := signerIdentityFromCertificate(r.Signature.Certificate)
	if err != nil {
		return nil, fmt.Errorf("extracting signer identity: %w", err)
	}
	return &Identity{
		SignerIdentity:      signer,
		CertIssuer:          r.Signature.Certificate.Issuer,
		SourceRepositoryURI: r.Signature.Certificate.SourceRepositoryURI,
	}, nil
}

// RetrieveBundles fetches the Sigstore bundles attached to imageRef, trying
// both layouts this package understands: a cosign-style signature manifest
// (the "sha256-<hex>.sig" tag) and attestation manifests. It returns
// ErrNoBundles when the artifact has no discoverable signature material —
// the caller's signal that the artifact is unsigned.
func RetrieveBundles(imageRef string, keychain authn.Keychain) ([]Bundle, error) {
	internal, err := getSigstoreBundles(imageRef, keychain)
	if errors.Is(err, ErrProvenanceNotFoundOrIncomplete) {
		return nil, ErrNoBundles
	}
	if err != nil {
		return nil, err
	}
	if len(internal) == 0 {
		return nil, ErrNoBundles
	}

	bundles := make([]Bundle, 0, len(internal))
	for _, b := range internal {
		raw, marshalErr := json.Marshal(b.bundle)
		if marshalErr != nil {
			return nil, fmt.Errorf("serializing sigstore bundle: %w", marshalErr)
		}
		bundles = append(bundles, Bundle{
			Parsed:     b.bundle,
			Raw:        raw,
			DigestAlgo: b.digestAlgo,
			DigestHex:  hex.EncodeToString(b.digestBytes),
		})
	}
	return bundles, nil
}

// OfflineTrustedMaterial returns trusted material for the Sigstore
// public-good instance built entirely from the trusted root embedded in this
// package — no network access, no TUF refresh. The embedded root is a
// point-in-time snapshot: key rotations in the public-good instance require
// a package update to pick up. Callers that need live freshness should use
// New (which performs a TUF fetch) instead.
func OfflineTrustedMaterial() (root.TrustedMaterial, error) {
	rawRoot, err := embeddedTufRoots.ReadFile(
		"tufroots/" + TrustedRootSigstorePublicGoodInstance + "/trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("reading embedded trusted root: %w", err)
	}
	tr, err := root.NewTrustedRootFromJSON(rawRoot)
	if err != nil {
		return nil, fmt.Errorf("parsing embedded trusted root: %w", err)
	}
	return tr, nil
}

// PublicKeyMaterial returns trusted material that verifies bundles signed
// with the private counterpart of the given PEM-encoded public key (the
// cosign key-pair flow, as opposed to keyless/Fulcio). The key is trusted
// without validity-period bounds: key-signed bundles carry no certificate
// whose lifetime could scope it.
func PublicKeyMaterial(pubKeyPEM []byte) (root.TrustedMaterial, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	sigVerifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading signature verifier: %w", err)
	}
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(sigVerifier, time.Time{}, time.Time{}), nil
	}), nil
}

// VerifyBundle verifies a retrieved bundle against the given trusted
// material. When expected is non-nil, the identity is bound into the
// Sigstore verification policy itself (certificate SAN and issuer must
// match) rather than compared after the fact; a nil expected — the
// trust-on-first-use case — verifies the chain of trust only, and the
// caller records the identity from the returned result.
//
// verifierOpts configure the verifier; when empty, the public-good
// instance defaults are used (SCT + transparency log + observer
// timestamps). Key-material verification (PublicKeyMaterial) must pass its
// own options, since key-signed bundles carry no certificate transparency
// or Fulcio timestamps.
func VerifyBundle(
	b Bundle,
	tm root.TrustedMaterial,
	expected *Identity,
	verifierOpts ...verify.VerifierOption,
) (*verify.VerificationResult, error) {
	if b.Parsed == nil {
		return nil, errors.New("bundle is not parsed")
	}
	if len(verifierOpts) == 0 {
		defaults, err := verifierOptions(TrustedRootSigstorePublicGoodInstance)
		if err != nil {
			return nil, err
		}
		verifierOpts = defaults
	}
	sev, err := verify.NewVerifier(tm, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}

	digestBytes, err := hex.DecodeString(b.DigestHex)
	if err != nil {
		return nil, fmt.Errorf("decoding artifact digest: %w", err)
	}
	policyOpts := []verify.PolicyOption{}
	identityOpt, err := identityPolicyOption(expected)
	if err != nil {
		return nil, err
	}
	policyOpts = append(policyOpts, identityOpt)

	result, err := sev.Verify(b.Parsed, verify.NewPolicy(
		verify.WithArtifactDigest(b.DigestAlgo, digestBytes),
		policyOpts...,
	))
	if err != nil {
		return nil, err
	}
	return result, nil
}

// VerifyBundleWithKey verifies a bundle signed with a plain key pair (the
// cosign --key flow) against the given PEM public key. Key-signed bundles
// carry no certificate, so there is no identity to bind — trust is the key
// itself — and no transparency-log or timestamp material to require.
func VerifyBundleWithKey(b Bundle, pubKeyPEM []byte) (*verify.VerificationResult, error) {
	if b.Parsed == nil {
		return nil, errors.New("bundle is not parsed")
	}
	tm, err := PublicKeyMaterial(pubKeyPEM)
	if err != nil {
		return nil, err
	}
	sev, err := verify.NewVerifier(tm, verify.WithNoObserverTimestamps())
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}
	digestBytes, err := hex.DecodeString(b.DigestHex)
	if err != nil {
		return nil, fmt.Errorf("decoding artifact digest: %w", err)
	}
	return sev.Verify(b.Parsed, verify.NewPolicy(
		verify.WithArtifactDigest(b.DigestAlgo, digestBytes),
		verify.WithKey(),
	))
}

// VerifyBundleOffline re-verifies a stored bundle (the Raw form produced by
// RetrieveBundles or a signing flow) against the artifact digest, using
// only the embedded trusted root — no network. See OfflineTrustedMaterial
// for the freshness trade-off. expected behaves as in VerifyBundle.
func VerifyBundleOffline(
	rawBundle []byte,
	digestAlgo, digestHex string,
	expected *Identity,
) (*verify.VerificationResult, error) {
	tm, err := OfflineTrustedMaterial()
	if err != nil {
		return nil, err
	}
	parsed := &bundle.Bundle{}
	if err := parsed.UnmarshalJSON(rawBundle); err != nil {
		return nil, fmt.Errorf("parsing stored bundle: %w", err)
	}
	return VerifyBundle(Bundle{
		Parsed:     parsed,
		Raw:        rawBundle,
		DigestAlgo: digestAlgo,
		DigestHex:  digestHex,
	}, tm, expected)
}

// identityPolicyOption translates an expected Identity into a Sigstore
// certificate-identity policy. For identities recorded from GitHub Actions
// certificates the SAN is the repository URI + workflow path (+ "@ref"), so
// the match is anchored by prefix; other identities match the SAN exactly.
func identityPolicyOption(expected *Identity) (verify.PolicyOption, error) {
	if expected == nil {
		//nolint:staticcheck // deliberate: TOFU first use has no identity to pin yet
		return verify.WithoutIdentitiesUnsafe(), nil
	}
	var certID verify.CertificateIdentity
	var err error
	if expected.SourceRepositoryURI != "" {
		// GitHub-Actions-derived identity: SAN = repoURI + workflowPath[@ref].
		sanRegex := "^" + regexp.QuoteMeta(expected.SourceRepositoryURI+expected.SignerIdentity) + "(@.*)?$"
		certID, err = verify.NewShortCertificateIdentity(expected.CertIssuer, "", "", sanRegex)
	} else {
		certID, err = verify.NewShortCertificateIdentity(expected.CertIssuer, "", expected.SignerIdentity, "")
	}
	if err != nil {
		return nil, fmt.Errorf("building certificate identity policy: %w", err)
	}
	return verify.WithCertificateIdentity(certID), nil
}

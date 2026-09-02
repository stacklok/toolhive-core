// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"crypto"
	"encoding/hex"
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
// Sigstore signature or attestation in any supported layout — keyless
// (certificate-bearing), key-signed ("cosign sign --key"), or attestation —
// i.e. the artifact is unsigned as far as this package can tell.
var ErrNoBundles = errors.New("no sigstore bundles found for artifact")

// ErrVerificationFailed wraps every cryptographic verification failure
// returned by the VerifyBundle* functions, so callers can distinguish
// "signed but failed verification" from malformed input with errors.Is
// instead of matching sigstore-go's (unstable) error strings.
var ErrVerificationFailed = errors.New("sigstore bundle verification failed")

// Bundle is a Sigstore bundle retrieved for an artifact, in both parsed and
// serialized form.
//
// # What a Bundle is bound to
//
// A Bundle is bound to the ARTIFACT digest, in every layout and both online
// and offline: DigestAlgo/DigestHex are the artifact's own manifest digest,
// and Raw round-trips through VerifyBundleOffline (or
// VerifyBundleOfflineWithKey for the key-signed layout — HasCertificate
// tells the two apart) against that same artifact digest. Callers never
// need to know that a cosign signature actually covers a payload blob
// rather than the artifact; SimpleSigningPayload carries whatever is needed
// to resolve that internally.
type Bundle struct {
	// Parsed is the decoded bundle.
	Parsed *bundle.Bundle
	// Raw is the bundle's durable serialization, suitable for storage and
	// later offline re-verification. It is bare Sigstore bundle JSON when
	// SimpleSigningPayload is empty, and the StoredBundleMediaType envelope
	// (bundle plus payload) when it is not — see EncodeStoredBundle.
	Raw []byte
	// DigestAlgo is the algorithm of the artifact digest the bundle binds
	// (e.g. "sha256").
	DigestAlgo string
	// DigestHex is the hex-encoded artifact manifest digest the bundle
	// binds. This is the artifact's digest, NOT the digest of the blob the
	// signature covers; for the cosign simple-signing layout those differ.
	DigestHex string
	// SimpleSigningPayload is the cosign simple-signing payload the
	// signature covers, for bundles reconstructed from a cosign signature
	// manifest (the "sha256-<hex>.sig" tag). It is empty for attestation
	// (referrer) bundles, whose in-toto subject already names the artifact.
	//
	// It is not decoration: the payload is the only thing tying such a
	// signature to an artifact, since the signature itself commits to these
	// bytes and nothing else. Verification checks the signature against
	// their digest AND checks that they name DigestHex.
	SimpleSigningPayload []byte
}

// HasCertificate reports whether the bundle carries a signing certificate —
// i.e. it came from a keyless (Fulcio) flow and verifies with VerifyBundle;
// a false result is the key-signed layout, verifying with
// VerifyBundleWithKey / VerifyBundleOfflineWithKey.
func (b Bundle) HasCertificate() bool {
	if b.Parsed == nil {
		return false
	}
	vm := b.Parsed.GetVerificationMaterial()
	return vm.GetCertificate() != nil || vm.GetX509CertificateChain() != nil
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
func IdentityFromResult(r *verify.VerificationResult) (Identity, error) {
	if r == nil || r.Signature == nil || r.Signature.Certificate == nil {
		return Identity{}, errors.New("verification result carries no certificate summary")
	}
	signer, err := signerIdentityFromCertificate(r.Signature.Certificate)
	if err != nil {
		return Identity{}, fmt.Errorf("extracting signer identity: %w", err)
	}
	return Identity{
		SignerIdentity:      signer,
		CertIssuer:          r.Signature.Certificate.Issuer,
		SourceRepositoryURI: r.Signature.Certificate.SourceRepositoryURI,
	}, nil
}

// RetrieveBundles fetches the Sigstore bundles attached to imageRef, trying
// both layouts this package understands: attestation manifests (the OCI 1.1
// referrers API) and a cosign-style signature manifest (the
// "sha256-<hex>.sig" tag). Every returned Bundle is bound to imageRef's own
// manifest digest — see Bundle.
//
// It returns ErrNoBundles when the artifact has no discoverable signature
// material — the caller's signal that the artifact is unsigned — and
// ErrSignatureArtifactMismatch when signature material WAS found but does
// not cover this artifact. Those are different answers and callers should
// treat them differently; a mismatch in particular must not be softened into
// "unsigned".
func RetrieveBundles(ctx context.Context, imageRef string, keychain authn.Keychain) ([]Bundle, error) {
	internal, err := getSigstoreBundles(ctx, imageRef, keychain)
	if errors.Is(err, ErrProvenanceNotFoundOrIncomplete) {
		return nil, fmt.Errorf("%w: %w", ErrNoBundles, err)
	}
	if err != nil {
		return nil, err
	}
	if len(internal) == 0 {
		return nil, ErrNoBundles
	}

	bundles := make([]Bundle, 0, len(internal))
	for _, b := range internal {
		// MarshalJSON is protojson under the hood — the canonical bundle
		// encoding; called explicitly so it doesn't rely on json.Marshal's
		// interface dispatch.
		bundleJSON, marshalErr := b.bundle.MarshalJSON()
		if marshalErr != nil {
			return nil, fmt.Errorf("serializing sigstore bundle: %w", marshalErr)
		}
		raw, encodeErr := EncodeStoredBundle(bundleJSON, b.payload)
		if encodeErr != nil {
			return nil, fmt.Errorf("serializing sigstore bundle: %w", encodeErr)
		}
		bundles = append(bundles, Bundle{
			Parsed:               b.bundle,
			Raw:                  raw,
			DigestAlgo:           b.digestAlgo,
			DigestHex:            hex.EncodeToString(b.digestBytes),
			SimpleSigningPayload: b.payload,
		})
	}
	return bundles, nil
}

// OfflineTrustedMaterial returns trusted material for the Sigstore
// public-good instance built entirely from the trusted root embedded in this
// package — no network access, no TUF refresh. The embedded root is a
// point-in-time snapshot: key rotations in the public-good instance require
// a package update to pick up. This cuts both ways — newly rotated-in keys
// are unknown (verification of fresh signatures fails until the snapshot is
// updated), and a key rotated out BECAUSE OF COMPROMISE keeps being trusted
// here until a new release ships and consumers bump. Callers that need live
// freshness or timely compromise revocation should use New (which performs
// a TUF fetch) instead; offline verification trades that for hermeticity.
// See tufroots/README.md for the snapshot's provenance.
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
// material, binding it to the artifact digest the bundle carries
// (Bundle.DigestAlgo/DigestHex). For a cosign simple-signing bundle that
// means both links of the chain: the signature is checked against the
// payload blob it covers, and the payload is checked to name this artifact —
// a payload naming a different artifact fails with
// ErrSignatureArtifactMismatch, not success.
//
// When expected is non-nil, the identity is bound into the
// Sigstore verification policy itself (certificate SAN and issuer must
// match) rather than compared after the fact; a nil expected — the
// trust-on-first-use case — verifies the chain of trust only, and the
// caller records the identity from the returned result.
//
// verifierOpts configure the verifier and MUST match the trusted material:
// pass DefaultVerifierOptions() with public-good material (SCT +
// transparency log + observer timestamps), and
// verify.WithNoObserverTimestamps() with PublicKeyMaterial (key-signed
// bundles carry no certificate transparency or Fulcio timestamps).
// Requiring the options explicitly prevents public-good defaults being fed
// to a different root, which surfaces as confusing sigstore-go internals
// rather than a clear mismatch.
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
		return nil, errors.New(
			"verifier options are required and must match the trusted material: " +
				"use DefaultVerifierOptions() for the Sigstore public-good instance " +
				"or verify.WithNoObserverTimestamps() for key material")
	}
	sev, err := verify.NewVerifier(tm, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("building verifier: %w", err)
	}

	artifactOpt, err := bundleArtifactPolicy(b)
	if err != nil {
		return nil, err
	}
	policyOpts := []verify.PolicyOption{}
	identityOpt, err := identityPolicyOption(expected)
	if err != nil {
		return nil, err
	}
	policyOpts = append(policyOpts, identityOpt)

	result, err := sev.Verify(b.Parsed, verify.NewPolicy(artifactOpt, policyOpts...))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return result, nil
}

// bundleArtifactPolicy builds the artifact-binding policy for an exported
// Bundle, resolving its artifact digest into whatever Sigstore has to be
// told — see artifactDigestPolicy for why those are not always the same
// value.
func bundleArtifactPolicy(b Bundle) (verify.ArtifactPolicyOption, error) {
	digestBytes, err := hex.DecodeString(b.DigestHex)
	if err != nil {
		return nil, fmt.Errorf("decoding artifact digest: %w", err)
	}
	return artifactDigestPolicy(b.SimpleSigningPayload, b.DigestAlgo, digestBytes)
}

// DefaultVerifierOptions returns the verifier options matching the Sigstore
// public-good instance trust root (SCT, transparency log, and observer
// timestamp requirements). Pass these to VerifyBundle together with
// OfflineTrustedMaterial (or the live public-good root).
func DefaultVerifierOptions() ([]verify.VerifierOption, error) {
	return verifierOptions(TrustedRootSigstorePublicGoodInstance)
}

// VerifyBundleWithKey verifies a bundle signed with a plain key pair (the
// cosign --key flow) against the given PEM public key, binding it to the
// artifact digest the bundle carries exactly as VerifyBundle does. Key-signed
// bundles carry no certificate, so there is no identity to bind — trust is
// the key itself — and no transparency-log or timestamp material to require.
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
	artifactOpt, err := bundleArtifactPolicy(b)
	if err != nil {
		return nil, err
	}
	result, err := sev.Verify(b.Parsed, verify.NewPolicy(artifactOpt, verify.WithKey()))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVerificationFailed, err)
	}
	return result, nil
}

// VerifyBundleOffline re-verifies a stored bundle (the [Bundle.Raw] form
// produced by RetrieveBundles or a signing flow) against the ARTIFACT digest,
// given as "sha256:<hex>", using only the embedded trusted root — no network.
// See OfflineTrustedMaterial for the freshness trade-off. expected behaves as
// in VerifyBundle.
//
// artifactDigest is the artifact's own manifest digest: the value a caller
// already has from a lock file, a registry entry, or a registry resolution.
// It is deliberately NOT the digest of the blob a cosign signature covers —
// callers do not need to know that such a blob exists. Where one does, the
// stored form carries it (see StoredBundleMediaType) and this function checks
// that it names artifactDigest, failing with ErrSignatureArtifactMismatch if
// it names something else.
func VerifyBundleOffline(
	rawBundle []byte,
	artifactDigest string,
	expected *Identity,
) (*verify.VerificationResult, error) {
	b, err := DecodeStoredBundle(rawBundle, artifactDigest)
	if err != nil {
		return nil, err
	}
	tm, err := OfflineTrustedMaterial()
	if err != nil {
		return nil, err
	}
	opts, err := DefaultVerifierOptions()
	if err != nil {
		return nil, err
	}
	return VerifyBundle(b, tm, expected, opts...)
}

// VerifyBundleOfflineWithKey re-verifies a stored key-signed bundle (the
// [Bundle.Raw] form of a bundle whose HasCertificate is false) against the
// ARTIFACT digest ("sha256:<hex>") and the given PEM public key. The digest
// contract is the same as VerifyBundleOffline's. Key verification needs no
// trust root or network in the first place; this entry point only adds the
// parse step for stored bundles.
func VerifyBundleOfflineWithKey(
	rawBundle []byte,
	artifactDigest string,
	pubKeyPEM []byte,
) (*verify.VerificationResult, error) {
	b, err := DecodeStoredBundle(rawBundle, artifactDigest)
	if err != nil {
		return nil, err
	}
	return VerifyBundleWithKey(b, pubKeyPEM)
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

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package signer signs OCI artifacts with Sigstore, following the cosign
// convention: a "simple signing" payload binding the artifact's manifest
// digest is signed, attached to the registry as a cosign signature manifest
// (the "sha256-<hex>.sig" tag), and returned as a serialized Sigstore bundle
// for durable storage and offline re-verification.
//
// Both cosign signing methods are supported, selected by [Options]: a
// file-based key pair ([Options.Key]) or keyless signing against Fulcio and
// Rekor with an OIDC identity token ([Options.IdentityToken]). Acquiring that
// token — ambient CI credentials, an interactive browser flow, a device
// flow — is entirely the caller's concern; this package never performs OAuth
// and only ever forwards the token it is handed to Fulcio.
//
// It is the signing counterpart to [github.com/stacklok/toolhive-core/container/verifier]:
// a key-signed bundle produced here verifies through that package's
// [verifier.VerifyBundleWithKey] and a keyless one through
// [verifier.VerifyBundle], and the attached manifest is the layout
// [verifier.RetrieveBundles] reconstructs from.
package signer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	verifybundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/stacklok/toolhive-core/container/verifier"
	"github.com/stacklok/toolhive-core/networking"
)

// Public-good Sigstore endpoints, used when Options leaves the corresponding
// URL empty.
//
// These are hardcoded rather than derived from a trusted root, deliberately.
// The trusted root does carry the deployment's URIs, but reading them means
// fetching a root (a TUF network round trip, or the point-in-time snapshot
// embedded in container/verifier) purely to learn a URL, and the URI is only
// reachable by type-asserting root.CertificateAuthority — a single-method
// Verify interface — to the concrete *root.FulcioCertificateAuthority. More
// importantly, the trusted root is verification material: keying signing
// endpoints off it would let a trust-root refresh silently redirect where
// signing requests, and the identity token in them, are sent. Signing
// against a different deployment is instead an explicit choice, made through
// Options.
const (
	// DefaultFulcioURL is the public-good Fulcio certificate authority.
	DefaultFulcioURL = "https://fulcio.sigstore.dev"
	// DefaultRekorURL is the public-good Rekor transparency log.
	DefaultRekorURL = "https://rekor.sigstore.dev"
)

// rekorAPIVersionV1 selects the Rekor v1 API in sign.RekorOptions.Version
// (sigstore-go accepts sign.RekorAPIVersions but keeps the version constants
// unexported). v1 is deliberate, not incidental: v2 issues proof-only entries
// and requires a separate timestamp authority, and the cosign bundle
// annotation this package attaches has no field for a v2 inclusion proof —
// only the v1 inclusion promise (a SignedEntryTimestamp) fits. See
// rekorBundleAnnotation.
const rekorAPIVersionV1 uint32 = 1

// keylessRetries is how many times a Fulcio or Rekor call is retried on a
// retryable (5xx, 429) response before signing fails.
const keylessRetries = 3

// ErrKeyRequired indicates no signing method was provided: signing needs
// either a cosign private key or an OIDC identity token for the keyless
// flow. Callers exposing a CLI should wrap this with the flags the user is
// expected to pass.
var ErrKeyRequired = errors.New(
	"no signing method provided: set Options.Key to a cosign private key, " +
		"or Options.IdentityToken to an OIDC identity token for keyless signing")

// ErrAmbiguousSigningMethod indicates both Options.Key and
// Options.IdentityToken were set. Rather than pick one, signing fails: the
// two produce materially different trust material — a bundle verifiers check
// against a bare public key, versus one they check against a Fulcio identity
// and the transparency log — so silently choosing would attach a signature
// the caller cannot verify the way it expects.
var ErrAmbiguousSigningMethod = errors.New(
	"conflicting signing methods: set exactly one of Options.Key or Options.IdentityToken")

// Options configures OCI signing. Exactly one signing method must be set:
// Key for the cosign key-pair flow, or IdentityToken for keyless signing.
// FulcioURL and RekorURL apply to keyless signing only and are ignored for
// the key-pair flow.
type Options struct {
	// Key is the path to a cosign PEM-encoded private key file. An
	// encrypted key is decrypted with the COSIGN_PASSWORD environment
	// variable, matching the cosign CLI.
	Key string
	// IdentityToken is a raw OIDC ID token (a JWT, as a plain string)
	// identifying the signer to Fulcio. Setting it selects the keyless
	// flow: a single-use ephemeral key pair is minted, Fulcio issues a
	// short-lived certificate binding it to the token's identity, and the
	// signature is submitted to Rekor. Obtaining the token is the caller's
	// responsibility — see the package doc.
	//
	// This token is sent as a bearer credential to FulcioURL, which is why
	// FulcioURL and RekorURL are validated to be HTTPS (loopback excepted,
	// for tests) before either is contacted — see keylessBundleOptions.
	IdentityToken string
	// FulcioURL overrides the certificate authority for keyless signing.
	// Empty means DefaultFulcioURL. Defaulting happens at signing time and
	// only when IdentityToken selects the keyless flow — a zero Options
	// value alone still errors with ErrKeyRequired, it does not sign
	// against the public-good deployment by default. Once IdentityToken IS
	// set, though, an empty FulcioURL/RekorURL is a deliberate posture
	// change from "no key ⇒ always error": keyless signing then performs
	// outbound network egress to public-good Sigstore services by default.
	FulcioURL string
	// RekorURL overrides the transparency log for keyless signing. Empty
	// means DefaultRekorURL, applied at signing time as with FulcioURL.
	// Only the Rekor v1 API is supported — see rekorAPIVersionV1.
	//
	// A Rekor entry is not optional: the verification policy this project's
	// container/verifier applies to keyless bundles requires a
	// transparency-log entry, so a bundle signed without one would not
	// verify.
	RekorURL string
}

// Result is the outcome of a signing operation.
type Result struct {
	// Bundle is the serialized Sigstore bundle, for durable storage and
	// later offline re-verification.
	//
	// Re-verify it against the ARTIFACT digest — the same digest passed to
	// SignOCI — with [verifier.VerifyBundleOffline] or
	// [verifier.VerifyBundleOfflineWithKey]. Bundle is not bare Sigstore
	// bundle JSON: it wraps the bundle together with the simple-signing
	// payload the signature covers, because that payload is the only thing
	// tying a cosign signature to an artifact. See
	// [verifier.StoredBundleMediaType] for the shape, and
	// [verifier.DecodeStoredBundle] to unwrap it.
	//
	// Its JSON shape is not stable across calls for the same identity: a
	// freshly attached signature wraps sign.Bundle's own bundle media type
	// (v0.3), while a signature this call deduped against (see
	// SignOCI's "one signature, two representations" doc) is reconstructed
	// by verifier.RetrieveBundles from the classic cosign annotations —
	// the v0.1 shape, carrying an inclusion promise rather than a proof.
	// Both verify identically; a caller comparing stored bundles byte-for-
	// byte across calls, or inspecting mediaType, will see this difference.
	Bundle []byte
	// PayloadDigest is the "<algorithm>:<hex>" digest of the simple-signing
	// payload the signature covers.
	//
	// It is NOT the artifact digest passed to SignOCI: following the cosign
	// convention, the signature covers a payload that *embeds* the artifact
	// digest rather than the digest itself. Verifying Bundle does not
	// require it — Bundle carries the payload, and the verifier entry points
	// take the artifact digest — so this is informational: it identifies the
	// blob in the attached signature manifest that this signature signs. See
	// [PayloadDigest] to recompute it from a reference and digest alone.
	PayloadDigest string
}

// Signer signs OCI artifacts and attaches the signature to the registry.
type Signer interface {
	// SignOCI signs the artifact at ref pinned to the given manifest digest
	// ("sha256:..."), attaches the signature as a cosign signature manifest
	// next to the artifact, and returns the bundle together with the digest
	// it signs.
	SignOCI(ctx context.Context, ref, digest string, opts Options) (*Result, error)
}

// Default implements Signer for both cosign signing methods: file-based key
// pairs and keyless signing via Fulcio and Rekor.
type Default struct {
	keychain authn.Keychain
	// trustedMaterial resolves the trust material keyless dedupe checks an
	// existing layer's certificate against (see keylessLayerTrusted). Nil in
	// every production Default — keylessTrustedMaterial falls back to
	// verifier.OfflineTrustedMaterial, the embedded public-good Sigstore
	// root, which is what DefaultFulcioURL/DefaultRekorURL actually issue
	// against. It exists as a field (not a hardcoded call) only so tests
	// signing against a synthetic Fulcio/Rekor deployment — one that, by
	// construction, cannot chain to the embedded production root — can
	// supply their own trust material and exercise dedupe actually firing,
	// not just the fail-closed path. See newDefaultForTest.
	trustedMaterial func() (root.TrustedMaterial, error)
}

var _ Signer = (*Default)(nil)

// NewDefault creates a signer using the given registry auth keychain for
// pushing the signature manifest. A nil keychain falls back to the default
// keychain.
func NewDefault(keychain authn.Keychain) *Default {
	if keychain == nil {
		keychain = authn.DefaultKeychain
	}
	return &Default{keychain: keychain}
}

// newDefaultForTest creates a signer whose keyless dedupe check verifies
// against tm instead of the embedded production Sigstore root — for tests
// signing against a synthetic Fulcio/Rekor deployment that cannot chain to
// the real one. Production code always uses NewDefault.
func newDefaultForTest(keychain authn.Keychain, tm root.TrustedMaterial) *Default {
	d := NewDefault(keychain)
	d.trustedMaterial = func() (root.TrustedMaterial, error) { return tm, nil }
	return d
}

// keylessTrustedMaterial resolves the trust material for keyless dedupe
// verification — see the doc comment on Default.trustedMaterial.
func (d *Default) keylessTrustedMaterial() (root.TrustedMaterial, error) {
	if d.trustedMaterial != nil {
		return d.trustedMaterial()
	}
	return verifier.OfflineTrustedMaterial()
}

// SignOCI signs the artifact following the cosign convention: the signature
// is computed over the simple-signing payload (which embeds the manifest
// digest, binding the signature to the artifact), the SAME signature is
// attached to the registry as a cosign signature manifest, and the returned
// bundle carries it with the payload's digest as the signed message. A
// verifier reconstructing the bundle from the registry manifest (or
// re-verifying the stored bundle offline) therefore checks exactly the
// signature that was attached — one signature, two representations.
//
// The signing method comes from opts: a file key, or keyless via Fulcio and
// Rekor. The two differ only in where the signing key and its trust material
// come from — everything downstream of sign.Bundle, including the attached
// manifest layout, is shared.
func (d *Default) SignOCI(ctx context.Context, ref, digestStr string, opts Options) (*Result, error) {
	keypair, bundleOpts, err := signingMaterial(ctx, opts)
	if err != nil {
		return nil, err
	}

	payload, err := SimpleSigningPayload(ref, digestStr)
	if err != nil {
		return nil, err
	}

	pb, err := signBundle(ctx, payload, keypair, bundleOpts, opts.IdentityToken != "")
	if err != nil {
		return nil, err
	}
	msgSig := pb.GetMessageSignature()
	if msgSig == nil || len(msgSig.GetSignature()) == 0 {
		return nil, errors.New("signing produced no message signature")
	}

	// Validated BEFORE the registry is touched: a malformed-but-parseable
	// response from Fulcio/Rekor could otherwise attach successfully and
	// only THEN fail validation below, returning an error despite having
	// already mutated the registry.
	if _, err := verifybundle.NewBundle(pb); err != nil {
		return nil, fmt.Errorf("validating sigstore bundle: %w", err)
	}

	tm, err := d.keylessTrustedMaterial()
	if err != nil {
		return nil, fmt.Errorf("loading trusted material: %w", err)
	}

	attached, err := attachCosignSignature(ctx, d.keychain, ref, digestStr, payload, pb, keypair.GetPublicKey(), tm)
	if err != nil {
		return nil, fmt.Errorf("attaching signature manifest: %w", err)
	}

	raw, err := resultBundleJSON(ctx, d.keychain, ref, digestStr, payload, pb, keypair.GetPublicKey(), tm, attached)
	if err != nil {
		return nil, err
	}
	return &Result{Bundle: raw, PayloadDigest: payloadDigest(payload)}, nil
}

// signBundle builds the sigstore bundle for payload. For the key-signed
// path (keyless false) this is a direct, synchronous call: no network is
// involved, so neither of the two problems keylessSignBundle exists to work
// around applies, and a panic here would be this package's own bug — it
// should propagate as one, not be reclassified as a Fulcio or Rekor
// problem with the real stack trace discarded.
func signBundle(
	ctx context.Context, payload []byte, keypair sign.Keypair, opts sign.BundleOptions, keyless bool,
) (*protobundle.Bundle, error) {
	if !keyless {
		pb, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, opts)
		if err != nil {
			return nil, fmt.Errorf("building sigstore bundle: %w", err)
		}
		return pb, nil
	}
	return keylessSignBundle(ctx, payload, keypair, opts)
}

// keylessSignBundle runs the keyless flow on its own goroutine so SignOCI
// honors ctx cancellation even though it cannot always rely on the
// underlying dependency to: sigstore-go's Fulcio client
// (pkg/sign.Fulcio.GetCertificate, as of sigstore-go v1.3.0) builds its HTTP
// request with http.NewRequest, not http.NewRequestWithContext, and only
// consults ctx between retries — once a request is actually in flight, a
// canceled ctx has no effect until the HTTP client's own timeout fires (30s
// by default). Racing ctx.Done() against the call lets a canceled SignOCI
// return promptly regardless; the abandoned goroutine still exits on its
// own once the underlying call completes or times out, so nothing leaks
// unbounded.
//
// The same goroutine boundary recovers a panic, for a related but distinct
// reason: sigstore/rekor's own response parsing
// (pkg/tle.GenerateTransparencyLogEntry, reached via sigstore-go's Rekor v1
// client) dereferences several Verification/InclusionProof response fields
// unconditionally, and a well-formed JSON response that simply omits that
// object — a misconfigured or non-standard Rekor deployment, not
// necessarily a hostile one — reaches that dereference and panics. SignOCI
// is this package's public API surface and, per the package doc, signing
// happens for the lifetime of a long-lived `thv serve` process; an
// unrecovered panic here would take the whole process down over a single
// bad network response. Scoping this boundary to the keyless path only
// (rather than wrapping signBundle's key-signed branch too, as an earlier
// version of this function did) keeps recover() scoped to untrusted
// external input, not to bugs in this package's own code.
//
// Fulcio and Rekor failures are distinguished by calling
// opts.CertificateProvider directly first — the exact call sign.Bundle
// would otherwise make internally, but with its error tagged as a Fulcio
// failure before sign.Bundle ever sees it — then handing sign.Bundle the
// already-fetched certificate via cachedCertificate, so its own internal
// GetCertificate call is a cache hit rather than a second Fulcio round
// trip. With this configuration (no TimestampAuthorities, no TrustedRoot),
// the only network call remaining inside sign.Bundle at that point is the
// Rekor submission, so a failure there is unambiguously tagged as Rekor's.
func keylessSignBundle(
	ctx context.Context, payload []byte, keypair sign.Keypair, opts sign.BundleOptions,
) (*protobundle.Bundle, error) {
	type signOutcome struct {
		pb  *protobundle.Bundle
		err error
	}
	outcome := make(chan signOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				outcome <- signOutcome{
					err: fmt.Errorf("signing failed unexpectedly (a Fulcio or Rekor response could not be processed): %v", r),
				}
			}
		}()
		fulcio := opts.CertificateProvider
		certDER, err := fulcio.GetCertificate(ctx, keypair, opts.CertificateProviderOptions)
		if err != nil {
			outcome <- signOutcome{err: fmt.Errorf("requesting signing certificate from Fulcio: %w", err)}
			return
		}
		cachedOpts := opts
		cachedOpts.CertificateProvider = &cachedCertificate{certDER: certDER}
		pb, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, cachedOpts)
		if err != nil {
			outcome <- signOutcome{err: fmt.Errorf("submitting to Rekor: %w", err)}
			return
		}
		outcome <- signOutcome{pb: pb}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-outcome:
		return res.pb, res.err
	}
}

// cachedCertificate is a sign.CertificateProvider that returns an
// already-fetched certificate without making another network call — see
// keylessSignBundle's doc comment for why.
type cachedCertificate struct {
	certDER []byte
}

func (c *cachedCertificate) GetCertificate(context.Context, sign.Keypair, *sign.CertificateProviderOptions) ([]byte, error) {
	return c.certDER, nil
}

// resultBundleJSON returns the serialized bundle that accurately reflects
// what is now on the registry, per attachCosignSignature's attached result.
//
// When attached is true, pb IS what was just written — "one signature, two
// representations," as documented on SignOCI. When attached is false,
// attachCosignSignature detected this identity/key had already signed the
// artifact and left the pre-existing layer alone: pb was built but never
// written anywhere, and every signing operation is randomised (a fresh
// ephemeral key and Fulcio certificate for keyless; ECDSA's own randomised
// nonce for a key re-sign), so pb's signature does not match what is
// actually attached. Returning pb in that case would violate the same
// contract from the other direction — the caller would hold a
// self-consistent bundle that nonetheless does not correspond to the
// artifact's actual registry state. The genuinely attached bundle is
// retrieved and returned instead.
func resultBundleJSON(
	ctx context.Context,
	keychain authn.Keychain,
	ref, digestStr string,
	payload []byte,
	pb *protobundle.Bundle,
	pub crypto.PublicKey,
	tm root.TrustedMaterial,
	attached bool,
) ([]byte, error) {
	if attached {
		bun, err := verifybundle.NewBundle(pb)
		if err != nil {
			return nil, fmt.Errorf("finalizing sigstore bundle: %w", err)
		}
		raw, err := bun.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("serializing sigstore bundle: %w", err)
		}
		// Persist the payload with the bundle. The signature covers the
		// payload, and only the payload names the artifact — a bundle
		// stored without it can be verified but no longer bound, which is
		// the difference between "someone signed this artifact" and
		// "someone signed something". See verifier.StoredBundleMediaType.
		stored, err := verifier.EncodeStoredBundle(raw, payload)
		if err != nil {
			return nil, fmt.Errorf("serializing sigstore bundle: %w", err)
		}
		return stored, nil
	}
	return previouslyAttachedBundleJSON(ctx, keychain, ref, digestStr, payload, pb, pub, tm)
}

// previouslyAttachedBundleJSON retrieves the signature layer that made this
// signing operation a no-op and returns its serialized bundle — the one
// genuinely on the registry, as opposed to the freshly (but never attached)
// built pb.
func previouslyAttachedBundleJSON(
	ctx context.Context,
	keychain authn.Keychain,
	ref, digestStr string,
	payload []byte,
	pb *protobundle.Bundle,
	pub crypto.PublicKey,
	tm root.TrustedMaterial,
) ([]byte, error) {
	full := ref
	if !strings.Contains(ref, "@") {
		full = ref + "@" + digestStr
	}
	bundles, err := verifier.RetrieveBundles(ctx, full, keychain)
	if err != nil {
		return nil, fmt.Errorf("retrieving previously attached signature: %w", err)
	}
	cert, err := certMaterialFromBundle(pb)
	if err != nil {
		return nil, err
	}
	var opts []verify.VerifierOption
	if cert != nil {
		// Only needed for the keyless chain-verification branch below;
		// loading it unconditionally would be wasted work on the
		// key-signed path, which never reaches keylessLayerTrusted.
		opts, err = verifier.DefaultVerifierOptions()
		if err != nil {
			return nil, fmt.Errorf("loading verifier options: %w", err)
		}
	}
	for _, b := range bundles {
		if bundleMatchesSigner(b, tm, opts, payload, cert, pub) {
			return b.Raw, nil
		}
	}
	return nil, errors.New("previously attached signature not found among the artifact's signature layers")
}

// bundleMatchesSigner reports whether b is the layer this signing operation
// deduped against: for keyless, a genuine, chain-verified Fulcio/Rekor
// signature from cert's identity over payload (see keylessLayerTrusted —
// identity match alone is not enough, since SAN and OIDC issuer are
// attacker-visible fields inside the certificate itself); for key-signed, a
// signature over payload that verifies with pub (never signature bytes,
// which ECDSA randomises on every call).
//
// This mirrors keylessAlreadySigned's keyless check exactly (both call
// keylessLayerTrusted) because they must agree: attach's dedupe decision
// and this selection must treat the same layer as "already signed" or not,
// or SignOCI could report success while returning material that doesn't
// correspond to what attach actually decided.
func bundleMatchesSigner(
	b verifier.Bundle, tm root.TrustedMaterial, opts []verify.VerifierOption,
	payload []byte, cert *certMaterial, pub crypto.PublicKey,
) bool {
	if b.Parsed == nil {
		return false
	}
	if cert != nil {
		return b.HasCertificate() && keylessLayerTrusted(b, tm, opts, payload, cert.summary)
	}
	msgSig := b.Parsed.GetMessageSignature()
	if msgSig == nil || len(msgSig.GetSignature()) == 0 {
		return false
	}
	sigVerifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return false
	}
	return sigVerifier.VerifySignature(bytes.NewReader(msgSig.GetSignature()), bytes.NewReader(payload)) == nil
}

// signingMaterial resolves opts into the key pair to sign with and the
// sign.Bundle options that establish its trust material, rejecting an absent
// or ambiguous signing method. Both branches return a sign.Keypair, which is
// the whole reason SignOCI needs no other knowledge of which flow is in play.
func signingMaterial(ctx context.Context, opts Options) (sign.Keypair, sign.BundleOptions, error) {
	switch {
	case opts.Key != "" && opts.IdentityToken != "":
		return nil, sign.BundleOptions{}, ErrAmbiguousSigningMethod
	case opts.Key != "":
		keypair, err := loadKeypair(opts.Key)
		if err != nil {
			return nil, sign.BundleOptions{}, err
		}
		return keypair, sign.BundleOptions{Context: ctx}, nil
	case opts.IdentityToken != "":
		// A fresh key pair per signature is the point of keyless signing:
		// the private key never outlives the call, and the certificate
		// Fulcio issues over it is what carries identity forward.
		keypair, err := sign.NewEphemeralKeypair(nil)
		if err != nil {
			return nil, sign.BundleOptions{}, fmt.Errorf("generating ephemeral signing key: %w", err)
		}
		bundleOpts, err := keylessBundleOptions(ctx, opts)
		if err != nil {
			return nil, sign.BundleOptions{}, err
		}
		return keypair, bundleOpts, nil
	default:
		return nil, sign.BundleOptions{}, ErrKeyRequired
	}
}

// keylessBundleOptions builds the sign.Bundle options for the keyless flow:
// Fulcio as the certificate provider for the ephemeral key, and Rekor v1 as
// the transparency log.
//
// TrustedRoot is deliberately left unset. sign.Bundle would otherwise verify
// the bundle it just produced, which needs a trusted root for the target
// deployment — a TUF fetch this package has no way to scope to a caller's
// custom FulcioURL/RekorURL. Verification is the caller's step, through
// container/verifier, against the root it decides to trust.
func keylessBundleOptions(ctx context.Context, opts Options) (sign.BundleOptions, error) {
	fulcioURL := opts.FulcioURL
	if fulcioURL == "" {
		fulcioURL = DefaultFulcioURL
	}
	rekorURL := opts.RekorURL
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	// IdentityToken goes out as an Authorization: Bearer header to fulcioURL
	// (sigstore-go's Fulcio client, unconditionally). A non-HTTPS,
	// non-loopback URL sends it in the clear — validated here, after
	// defaulting, so both the caller-supplied and the default case are
	// covered by one check. Loopback stays permitted for tests, which need
	// a plain-HTTP fake Fulcio/Rekor.
	if err := networking.ValidateEndpointURL(fulcioURL); err != nil {
		return sign.BundleOptions{}, fmt.Errorf("FulcioURL: %w", err)
	}
	if err := networking.ValidateEndpointURL(rekorURL); err != nil {
		return sign.BundleOptions{}, fmt.Errorf("RekorURL: %w", err)
	}
	return sign.BundleOptions{
		Context: ctx,
		CertificateProvider: sign.NewFulcio(&sign.FulcioOptions{
			BaseURL: fulcioURL,
			Retries: keylessRetries,
		}),
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: opts.IdentityToken},
		TransparencyLogs: []sign.Transparency{
			sign.NewRekor(&sign.RekorOptions{
				BaseURL: rekorURL,
				Retries: keylessRetries,
				Version: rekorAPIVersionV1,
			}),
		},
	}, nil
}

// PayloadDigest returns the digest of the simple-signing payload that a
// signature over the artifact at ref pinned to digestStr covers.
//
// Consumers verifying a stored bundle generally hold only the reference and
// the artifact digest — not the [Result] from signing — so this is the
// supported way to recover the value a bundle verifier needs.
func PayloadDigest(imageRef, digestStr string) (string, error) {
	payload, err := SimpleSigningPayload(imageRef, digestStr)
	if err != nil {
		return "", err
	}
	return payloadDigest(payload), nil
}

func payloadDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

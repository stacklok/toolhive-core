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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	verifybundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/sign"
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
	IdentityToken string
	// FulcioURL overrides the certificate authority for keyless signing.
	// Empty means DefaultFulcioURL; the default is applied at signing time,
	// so a zero Options value targets the public-good deployment.
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
	Bundle []byte
	// PayloadDigest is the "<algorithm>:<hex>" digest of the simple-signing
	// payload the bundle actually signs.
	//
	// This is deliberately surfaced because it is NOT the artifact digest
	// passed to SignOCI. Following the cosign convention, the signature
	// covers a payload that *embeds* the artifact digest rather than the
	// digest itself, so verifying Bundle offline requires this value —
	// passing the artifact digest to a bundle verifier will always fail.
	// See [PayloadDigest] to recompute it from a reference and digest alone.
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

	// sign.Bundle invokes the keypair's SignData over the payload and
	// records both the signature and the payload digest in the bundle. On
	// the keyless path it additionally calls Fulcio for a certificate over
	// the ephemeral key and submits the signature to Rekor, folding both
	// into the bundle's verification material.
	pb, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("building sigstore bundle: %w", err)
	}
	msgSig := pb.GetMessageSignature()
	if msgSig == nil || len(msgSig.GetSignature()) == 0 {
		return nil, errors.New("signing produced no message signature")
	}

	if err := attachCosignSignature(
		ctx, d.keychain, ref, digestStr, payload, pb, keypair.GetPublicKey(),
	); err != nil {
		return nil, fmt.Errorf("attaching signature manifest: %w", err)
	}

	bun, err := verifybundle.NewBundle(pb)
	if err != nil {
		return nil, fmt.Errorf("finalizing sigstore bundle: %w", err)
	}
	raw, err := bun.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("serializing sigstore bundle: %w", err)
	}
	return &Result{Bundle: raw, PayloadDigest: payloadDigest(payload)}, nil
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
		return keypair, keylessBundleOptions(ctx, opts), nil
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
func keylessBundleOptions(ctx context.Context, opts Options) sign.BundleOptions {
	fulcioURL := opts.FulcioURL
	if fulcioURL == "" {
		fulcioURL = DefaultFulcioURL
	}
	rekorURL := opts.RekorURL
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
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
	}
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

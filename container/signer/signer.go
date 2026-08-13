// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package signer signs OCI artifacts with Sigstore, following the
// cosign key-pair convention: a "simple signing" payload binding the
// artifact's manifest digest is signed with the user's key, attached to the
// registry as a cosign signature manifest (the "sha256-<hex>.sig" tag), and
// returned as a serialized Sigstore bundle for durable storage and offline
// re-verification.
//
// It is the signing counterpart to [github.com/stacklok/toolhive-core/container/verifier]:
// a bundle produced here verifies through that package's
// [verifier.VerifyBundleWithKey], and the attached manifest is the layout
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

// ErrKeyRequired indicates no signing key was provided. Keyless (OIDC)
// signing is not implemented yet, so a cosign private key is the only
// supported signing method. Callers exposing a CLI should wrap this with
// the flag the user is expected to pass.
var ErrKeyRequired = errors.New("signing key required: a cosign private key is needed to sign")

// Options configures OCI signing.
type Options struct {
	// Key is the path to a cosign PEM-encoded private key file. An
	// encrypted key is decrypted with the COSIGN_PASSWORD environment
	// variable, matching the cosign CLI.
	Key string
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

// Default implements Signer with file-based cosign keys.
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
func (d *Default) SignOCI(ctx context.Context, ref, digestStr string, opts Options) (*Result, error) {
	if opts.Key == "" {
		return nil, ErrKeyRequired
	}
	keypair, err := loadKeypair(opts.Key)
	if err != nil {
		return nil, err
	}

	payload, err := SimpleSigningPayload(ref, digestStr)
	if err != nil {
		return nil, err
	}

	// sign.Bundle invokes the keypair's SignData over the payload and
	// records both the signature and the payload digest in the bundle.
	pb, err := sign.Bundle(&sign.PlainData{Data: payload}, keypair, sign.BundleOptions{Context: ctx})
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

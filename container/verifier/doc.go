// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package verifier verifies Sigstore signatures and attestations on OCI
// artifacts.
//
// Two entry points cover the two trust flows:
//
//   - [New] builds a [Sigstore] verifier with a live TUF-refreshed trust
//     root for verifying MCP server images against registry-declared
//     provenance ([Sigstore.VerifyServer]).
//   - [RetrieveBundles], [VerifyBundle], [VerifyBundleWithKey], and
//     [VerifyBundleOffline] expose the bundle-level building blocks for
//     consumers that manage their own trust decisions — retrieving the
//     bundles attached to an artifact, verifying them against keyless
//     (Fulcio) or key-pair material, binding an expected [Identity] into
//     the verification policy, and re-verifying stored bundles offline
//     against the embedded trust root.
//
// # Verifying a retrieved bundle
//
//	bundles, err := verifier.RetrieveBundles(ctx, imageRef, keychain)
//	// handle err; errors.Is(err, verifier.ErrNoBundles) means unsigned, and
//	// errors.Is(err, verifier.ErrSignatureArtifactMismatch) means a signature
//	// was found that does not cover this artifact — a different verdict
//	tm, _ := verifier.OfflineTrustedMaterial()
//	opts, _ := verifier.DefaultVerifierOptions()
//	result, err := verifier.VerifyBundle(bundles[0], tm, nil, opts...)
//	// errors.Is(err, verifier.ErrVerificationFailed) means signed but invalid
//	identity, _ := verifier.IdentityFromResult(result)
//	// store bundles[0].Raw and identity; later:
//	_, err = verifier.VerifyBundleOffline(storedRaw, "sha256:"+artifactHex, &identity)
//
// Key-signed bundles (Bundle.HasCertificate() == false, the "cosign sign
// --key" layout) carry no certificate identity; verify them with
// VerifyBundleWithKey at retrieval time and VerifyBundleOfflineWithKey for
// stored Raw bytes — both take the signer's PEM public key.
//
// # What a bundle is bound to
//
// Every [Bundle] — retrieved, in memory, or stored — is bound to the
// ARTIFACT's own manifest digest, and that is the digest the offline entry
// points take. Callers never handle the digest of the blob a signature
// covers.
//
// That distinction is not cosmetic. Two layouts are supported and they bind
// differently:
//
//   - An attestation (OCI 1.1 referrer) bundle carries an in-toto statement
//     whose subject is the artifact digest. It is bound structurally.
//   - A cosign signature covers a "simple signing" payload blob, and it is
//     that payload — not the signature — that names the artifact, in
//     critical.image.docker-manifest-digest. Verifying the signature alone
//     proves someone signed something; the payload is what says what.
//     Retrieval, verification, and offline re-verification all check it, and
//     a payload naming a different artifact fails with
//     ErrSignatureArtifactMismatch.
//
// Because that payload is the binding, it has to survive storage:
// [Bundle.Raw] for a cosign signature is a small envelope carrying the
// Sigstore bundle together with the payload (see [StoredBundleMediaType]).
// Attestation bundles need no payload and are stored as plain Sigstore
// bundle JSON. Callers can treat Raw as opaque either way —
// [DecodeStoredBundle] reads both.
//
// # Stability
//
// This package is Alpha stability. The API may change without notice.
package verifier

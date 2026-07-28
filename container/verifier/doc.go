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
//	// handle err; errors.Is(err, verifier.ErrNoBundles) means unsigned
//	tm, _ := verifier.OfflineTrustedMaterial()
//	opts, _ := verifier.DefaultVerifierOptions()
//	result, err := verifier.VerifyBundle(bundles[0], tm, nil, opts...)
//	// errors.Is(err, verifier.ErrVerificationFailed) means signed but invalid
//	identity, _ := verifier.IdentityFromResult(result)
//	// store bundles[0].Raw and identity; later:
//	_, err = verifier.VerifyBundleOffline(storedRaw, "sha256:"+digestHex, &identity)
//
// Key-signed bundles (Bundle.HasCertificate() == false, the "cosign sign
// --key" layout) carry no certificate identity; verify them with
// VerifyBundleWithKey at retrieval time and VerifyBundleOfflineWithKey for
// stored Raw bytes — both take the signer's PEM public key.
//
// # Stability
//
// This package is Alpha stability. The API may change without notice.
package verifier

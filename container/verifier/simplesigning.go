// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// CosignSignatureType is the value cosign writes into a simple-signing
// payload's "critical.type" field. A payload carrying anything else is not a
// container image signature and must not be accepted as one.
const CosignSignatureType = "cosign container image signature"

// ErrSignatureArtifactMismatch is returned when a cosign simple-signing
// signature was found for an artifact but the signed payload does not bind
// to that artifact: the payload's critical.type is not a container image
// signature, or its critical.image.docker-manifest-digest names a different
// artifact.
//
// This is deliberately distinct from ErrNoBundles /
// ErrProvenanceNotFoundOrIncomplete. Cosign signatures are discovered at the
// mutable "sha256-<hex>.sig" tag, so a signature being present says nothing
// about which artifact it covers — and "a signature that does not cover this
// artifact" is a materially different verdict from "no signature at all".
// Collapsing the two would report a rejected signature as merely unsigned,
// which is the weaker and more easily ignored answer.
var ErrSignatureArtifactMismatch = errors.New("signature does not bind to this artifact")

// simpleSigningPayload is the subset of the cosign simple-signing payload
// that carries the signature's binding to an artifact. The signature covers
// these bytes; the bytes name the artifact. Verifying only the first half of
// that chain accepts a valid signature for artifact A as proof that
// artifact B is signed.
type simpleSigningPayload struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

// checkSimpleSigningBinding verifies the second link of the cosign
// simple-signing chain: that the signed payload actually claims the artifact
// identified by digestAlgo/digestHex. The first link — that the signature
// covers these payload bytes — is Sigstore's job, driven by the artifact
// policy artifactDigestPolicy builds.
//
// repoName, when non-empty, is the repository the artifact was resolved in
// and is compared against the payload's critical.identity.docker-reference.
// A mismatch there is logged, not rejected: see logRepositoryMismatch.
//
// Every failure wraps ErrSignatureArtifactMismatch so callers can tell a
// substituted signature from an absent one.
func checkSimpleSigningBinding(payload []byte, digestAlgo, digestHex, repoName string) error {
	var ss simpleSigningPayload
	if err := json.Unmarshal(payload, &ss); err != nil {
		return fmt.Errorf("%w: simple-signing payload is not valid JSON: %s", ErrSignatureArtifactMismatch, err.Error())
	}

	if ss.Critical.Type != CosignSignatureType {
		return fmt.Errorf("%w: payload critical.type is %q, want %q",
			ErrSignatureArtifactMismatch, ss.Critical.Type, CosignSignatureType)
	}

	claimed := ss.Critical.Image.DockerManifestDigest
	if claimed == "" {
		return fmt.Errorf("%w: payload carries no critical.image.docker-manifest-digest",
			ErrSignatureArtifactMismatch)
	}
	claimedAlgo, claimedHex, ok := strings.Cut(claimed, ":")
	if !ok || claimedAlgo == "" || claimedHex == "" {
		return fmt.Errorf("%w: payload docker-manifest-digest %q is not in <algorithm>:<hex> form",
			ErrSignatureArtifactMismatch, claimed)
	}
	// Hex is compared case-insensitively (registries and tools differ on
	// casing); the algorithm name is lower-case by spec but normalised the
	// same way rather than relying on the producer.
	if !strings.EqualFold(claimedAlgo, digestAlgo) || !strings.EqualFold(claimedHex, digestHex) {
		return fmt.Errorf("%w: signature covers %s, not %s:%s",
			ErrSignatureArtifactMismatch, claimed, digestAlgo, digestHex)
	}

	logRepositoryMismatch(ss.Critical.Identity.DockerReference, repoName)
	return nil
}

// logRepositoryMismatch reports a payload whose docker-reference names a
// different repository than the one the artifact was resolved in.
//
// This is a warning rather than a rejection, deliberately. The digest check
// above is what binds a signature to an artifact, and it is complete: a
// signature only passes it if the signer signed a payload naming this exact
// manifest digest, which no attacker can obtain for content the signer never
// signed. What docker-reference adds is only "the signer was looking at this
// repository at the time" — and enforcing it would break signature-preserving
// copies (mirrors, promotion between registries, air-gapped imports), where
// the artifact and its signature are both genuine and merely live somewhere
// else. Cosign's own verification does not enforce it either. The mismatch is
// still worth surfacing, because a legitimate copy and a confused deployment
// look the same from here.
func logRepositoryMismatch(dockerReference, repoName string) {
	if repoName == "" || dockerReference == "" {
		return
	}
	claimedRepo, err := name.NewRepository(dockerReference, name.WeakValidation)
	if err != nil {
		slog.Warn("simple-signing payload carries an unparseable docker-reference",
			"docker_reference", dockerReference, "repository", repoName, "error", err)
		return
	}
	if claimedRepo.Name() != repoName {
		slog.Warn("simple-signing payload was made for a different repository "+
			"(the artifact digest binding still holds; this is expected for a copied or mirrored artifact)",
			"docker_reference", claimedRepo.Name(), "repository", repoName)
	}
}

// artifactDigestPolicy builds the Sigstore artifact-binding policy for a
// bundle whose artifact digest is digestAlgo/digestBytes.
//
// The two layouts this package handles bind to the artifact differently, and
// the difference is the whole point of this function:
//
//   - An attestation (referrer) bundle carries an in-toto statement whose
//     subject IS the artifact digest, so the artifact digest goes straight
//     into the policy.
//   - A cosign simple-signing bundle's signature covers the payload blob,
//     not the artifact. Sigstore is therefore given the PAYLOAD digest — it
//     would reject anything else, since that is what the signature commits
//     to — and the payload's own claim about which artifact it covers is
//     checked here instead.
//
// The repository comparison is skipped: this runs on the verification path,
// including offline, where there is no registry context to compare against.
// Retrieval, which does have it, passes it — and only logs a mismatch, so
// nothing is lost by omitting it here.
func artifactDigestPolicy(payload []byte, digestAlgo string, digestBytes []byte) (verify.ArtifactPolicyOption, error) {
	if len(payload) == 0 {
		return verify.WithArtifactDigest(digestAlgo, digestBytes), nil
	}
	sum := sha256.Sum256(payload)
	if err := checkSimpleSigningBinding(payload, digestAlgo, hex.EncodeToString(digestBytes), ""); err != nil {
		return nil, annotatePayloadDigestMisuse(err, digestAlgo, digestBytes, sum[:])
	}
	return verify.WithArtifactDigest(DigestAlgorithmSHA256, sum[:]), nil
}

// annotatePayloadDigestMisuse recognises one specific way a caller can get
// the artifact digest wrong and says so, instead of leaving them with a bare
// "signature covers X, not Y".
//
// Before this package bound signatures to the artifact, a caller holding a
// stored cosign bundle had to compute the digest of the simple-signing
// payload themselves and pass that. Now the payload travels with the bundle
// and the entry points take the artifact digest, so that older call shape
// arrives here as a mismatch — correctly refused, since a digest derived
// from the payload proves nothing about which artifact it names, but
// mystifying if reported as though the signature were substituted. The two
// cases are distinguishable: only a caller passing the payload's own digest
// hands us a value equal to it.
func annotatePayloadDigestMisuse(err error, digestAlgo string, digestBytes, payloadDigest []byte) error {
	if digestAlgo != DigestAlgorithmSHA256 || !bytes.Equal(digestBytes, payloadDigest) {
		return err
	}
	return fmt.Errorf("%w: the digest given is the simple-signing payload's own digest, "+
		"not the artifact's; pass the artifact's manifest digest — the payload is carried "+
		"in the stored bundle and no longer has to be supplied", ErrSignatureArtifactMismatch)
}

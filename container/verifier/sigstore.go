// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package verifier provides a client for verifying artifacts using sigstore
package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Limits on the work a single signature manifest can cause. Both the layer
// list and the blobs it points at are registry-supplied: a manifest can name
// arbitrarily many simple-signing layers, and each one turned into a blob
// fetch would let whoever serves that manifest drive an unbounded number of
// authenticated requests (and log lines) out of one verification.
//
// The numbers are far above any real signature manifest — cosign writes one
// layer per signature, so even a heavily co-signed artifact stays in single
// digits, and a simple-signing payload is a few hundred bytes of JSON.
//
// maxSimpleSigningLayers bounds how many layers of one manifest are
// processed. The legacy retrieval API ignores layers past it; strict
// retrieval reports that it could not assess the complete bundle set.
// maxSimpleSigningPayloadTotalBytes bounds the total blob bytes read across
// all of a manifest's layers, on top of the per-blob cap.
const maxSimpleSigningLayers = 32

var maxSimpleSigningPayloadTotalBytes = MaxAttestationsBytesLimit

// sigstoreBundle is a bundle reconstructed for an artifact, together with
// what binds it to that artifact.
//
// digestAlgo/digestBytes are always the ARTIFACT's own manifest digest.
// payload is the cosign simple-signing payload the signature covers, set
// only for bundles reconstructed from a cosign signature manifest; it is
// what makes those bundles bindable at all (see artifactDigestPolicy).
type sigstoreBundle struct {
	bundle      *bundle.Bundle
	digestBytes []byte
	digestAlgo  string
	payload     []byte
}

// signatureTarget is everything needed to look up an artifact's cosign
// signatures AND to check that what is found actually covers that artifact.
// All three fields come from a single resolution of the reference, so the
// binding check cannot be skewed by a mutable tag moving between two
// lookups.
type signatureTarget struct {
	// sigTag is the "sha256-<hex>.sig" tag the signature manifest lives at.
	// It is an ordinary, mutable tag: anyone who can write tags in the
	// repository can point it at any signature manifest, including a
	// genuine one copied from an unrelated artifact. That is precisely why
	// artifactDigest below has to be checked against the signed payload.
	sigTag name.Tag
	// artifactDigest is the artifact's resolved manifest digest — the value
	// a signature's payload must name to count as covering it.
	artifactDigest v1.Hash
	// repo is the repository the artifact was resolved in.
	repo name.Repository
}

// bundleFromSigstoreSignedImage returns a bundle from a Sigstore signed image
func bundleFromSigstoreSignedImage(ctx context.Context, imageRef string, keychain authn.Keychain) ([]sigstoreBundle, error) {
	// Get the signature manifest from the OCI image reference, along with
	// the artifact digest each signature has to bind to
	target, err := getSignatureReferenceFromOCIImage(ctx, imageRef, keychain)
	if err != nil {
		return nil, fmt.Errorf("error getting signature reference from OCI image: %w", err)
	}
	return bundleFromSigstoreSignedTarget(ctx, target, keychain, false)
}

// bundleFromSigstoreSignedTarget retrieves cosign signature bundles for an
// already-resolved artifact. In strict mode, absence of the signature tag is
// still ordinary absence, but failures that prevent inspecting every
// potentially relevant layer are reported as ErrBundleSetIncomplete.
func bundleFromSigstoreSignedTarget(
	ctx context.Context,
	target signatureTarget,
	keychain authn.Keychain,
	strict bool,
) ([]sigstoreBundle, error) {
	simpleSigningLayers, err := getSimpleSigningLayers(ctx, target, keychain, strict)
	if err != nil {
		return nil, err
	}
	artifactDigestBytes, err := hex.DecodeString(target.artifactDigest.Hex)
	if err != nil {
		return nil, fmt.Errorf("error decoding artifact digest: %w", err)
	}

	var bundles []sigstoreBundle
	var rejected error
	payloads := simpleSigningPayloadCache{
		values: make(map[string][]byte, len(simpleSigningLayers)),
		budget: maxSimpleSigningPayloadTotalBytes,
	}
	for _, layer := range simpleSigningLayers {
		payload, usable, err := payloads.get(ctx, target, layer, keychain, strict)
		if err != nil {
			return nil, err
		}
		if !usable {
			continue
		}
		b, err := sigstoreBundleFromSimpleSigningLayer(layer, target, artifactDigestBytes, payload)
		if err != nil {
			if errors.Is(err, ErrSignatureArtifactMismatch) {
				rejected = err
				slog.Warn("rejecting signature layer that does not cover this artifact",
					"layer_digest", layer.Digest.String(), "error", err)
			} else {
				slog.Error("error constructing sigstore bundle",
					"layer_digest", layer.Digest.String(), "error", err)
			}
			continue
		}
		bundles = append(bundles, b)
	}

	if len(bundles) == 0 {
		if rejected != nil {
			return nil, rejected
		}
		return nil, ErrProvenanceNotFoundOrIncomplete
	}

	// Return the bundles
	return bundles, nil
}

func getSimpleSigningLayers(
	ctx context.Context,
	target signatureTarget,
	keychain authn.Keychain,
	strict bool,
) ([]v1.Descriptor, error) {
	var (
		layers []v1.Descriptor
		err    error
	)
	if strict {
		layers, err = getSimpleSigningLayersFromSignatureTargetStrict(ctx, target, keychain)
	} else {
		layers, err = getSimpleSigningLayersFromSignatureManifest(ctx, target.sigTag.Name(), keychain)
	}
	if err != nil {
		if strict && isManifestNotFound(err, target.sigTag) {
			return nil, ErrProvenanceNotFoundOrIncomplete
		}
		if strict {
			return nil, bundleSetIncompleteBecause(err, "reading cosign signature manifest")
		}
		return nil, fmt.Errorf("%w: %s", ErrProvenanceNotFoundOrIncomplete, err.Error())
	}
	if len(layers) <= maxSimpleSigningLayers {
		return layers, nil
	}
	if strict {
		return nil, bundleSetIncompletef(
			"cosign signature manifest has %d simple-signing layers; limit is %d",
			len(layers), maxSimpleSigningLayers)
	}
	slog.Warn("signature manifest carries more simple signing layers than will be processed",
		"layers", len(layers), "limit", maxSimpleSigningLayers)
	return layers[:maxSimpleSigningLayers], nil
}

type simpleSigningPayloadCache struct {
	values map[string][]byte
	budget int64
}

func (c *simpleSigningPayloadCache) get(
	ctx context.Context,
	target signatureTarget,
	layer v1.Descriptor,
	keychain authn.Keychain,
	strict bool,
) ([]byte, bool, error) {
	digest := layer.Digest.String()
	if payload, ok := c.values[digest]; ok {
		return payload, true, nil
	}
	if strict && layer.Digest.Algorithm != DigestAlgorithmSHA256 {
		return nil, false, bundleSetIncompletef(
			"simple-signing payload %s uses unsupported digest algorithm %s",
			digest, layer.Digest.Algorithm)
	}
	readLimit := min(c.budget, MaxAttestationsBytesLimit)
	if strict && (readLimit <= 0 || layer.Size > readLimit) {
		return nil, false, bundleSetIncompletef(
			"simple-signing payload %s exceeds the remaining retrieval limit", digest)
	}
	payload, err := fetchSimpleSigningPayload(ctx, target.repo, layer, keychain, c.budget, strict)
	if err != nil {
		if strict && errors.Is(err, ErrBundleSetIncomplete) {
			return nil, false, err
		}
		if strict && isBundleMaterialFetchError(err) {
			return nil, false, bundleSetIncompleteBecause(
				err, "fetching simple-signing payload %s", digest)
		}
		slog.Error("error fetching simple signing payload", "layer_digest", digest, "error", err)
		return nil, false, nil
	}
	c.budget -= int64(len(payload))
	c.values[digest] = payload
	return payload, true, nil
}

func sigstoreBundleFromSimpleSigningLayer(
	layer v1.Descriptor,
	target signatureTarget,
	artifactDigestBytes []byte,
	payload []byte,
) (sigstoreBundle, error) {
	if err := checkSimpleSigningBinding(
		payload, target.artifactDigest.Algorithm, target.artifactDigest.Hex, target.repo.Name(),
	); err != nil {
		return sigstoreBundle{}, err
	}
	verificationMaterial, err := getBundleVerificationMaterial(layer)
	if err != nil {
		return sigstoreBundle{}, fmt.Errorf("getting bundle verification material: %w", err)
	}
	msgSignature, err := getBundleMsgSignature(layer)
	if err != nil {
		return sigstoreBundle{}, fmt.Errorf("getting bundle message signature: %w", err)
	}
	pbb := protobundle.Bundle{
		MediaType:            sigstoreBundleMediaType01,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewBundle(&pbb)
	if err != nil {
		return sigstoreBundle{}, fmt.Errorf("creating protobuf bundle: %w", err)
	}
	return sigstoreBundle{
		bundle:      bun,
		digestAlgo:  target.artifactDigest.Algorithm,
		digestBytes: artifactDigestBytes,
		payload:     payload,
	}, nil
}

// fetchSimpleSigningPayload downloads the blob a simple-signing layer
// descriptor points at and returns its bytes.
//
// budget is the remaining share of maxSimpleSigningPayloadTotalBytes; the
// read is capped at the smaller of it and the per-blob limit. Truncation is
// not silent: a short read fails the digest check below, so an oversized blob
// is refused rather than half-parsed.
//
// The returned bytes are checked against the descriptor digest before being
// handed back. That check is not redundant with the registry client's own:
// the read is capped (the blob is untrusted, registry-supplied data), and a
// capped read that stops short of EOF never reaches the client's
// verification. It also matters for correctness downstream — the descriptor
// digest is what the reconstructed bundle's message signature commits to, so
// a payload that hashes to anything else would be verified against a digest
// it does not have.
func fetchSimpleSigningPayload(
	ctx context.Context,
	repo name.Repository,
	layer v1.Descriptor,
	keychain authn.Keychain,
	budget int64,
	strict bool,
) ([]byte, error) {
	if layer.Digest.Algorithm != DigestAlgorithmSHA256 {
		return nil, fmt.Errorf("unsupported simple signing layer digest algorithm: %s", layer.Digest.Algorithm)
	}
	if budget <= 0 {
		return nil, errors.New("simple signing payload budget for this manifest is exhausted")
	}
	remoteLayer, err := remote.Layer(
		repo.Digest(layer.Digest.String()),
		remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx),
	)
	if err != nil {
		return nil, markBundleMaterialFetchError(fmt.Errorf("error fetching simple signing blob: %w", err))
	}
	rc, err := remoteLayer.Compressed()
	if err != nil {
		return nil, markBundleMaterialFetchError(fmt.Errorf("error reading simple signing blob: %w", err))
	}
	defer func() { _ = rc.Close() }()

	readLimit := min(budget, MaxAttestationsBytesLimit)
	readerLimit := readLimit
	if strict {
		// Read one bounded byte beyond the accepted limit so strict retrieval
		// can distinguish truncation from completely read malformed content.
		readerLimit++
	}
	payload, err := io.ReadAll(io.LimitReader(rc, readerLimit))
	if err != nil {
		return nil, markBundleMaterialFetchError(fmt.Errorf("error reading simple signing blob: %w", err))
	}
	if strict && int64(len(payload)) > readLimit {
		return nil, bundleSetIncompletef(
			"simple-signing payload %s exceeds the retrieval limit", layer.Digest.String())
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != strings.ToLower(layer.Digest.Hex) {
		return nil, fmt.Errorf("simple signing blob does not match its descriptor digest %s", layer.Digest.String())
	}
	return payload, nil
}

// isManifestNotFound reports the registry's ordinary "this signature tag does
// not exist" answer. Authentication services can also return transport-level
// 404s; only the exact registry manifest request is layout absence.
func isManifestNotFound(err error, signatureTag name.Tag) bool {
	var transportErr *transport.Error
	if !errors.As(err, &transportErr) || transportErr.StatusCode != http.StatusNotFound ||
		transportErr.Request == nil || !manifestRequestTarget(signatureTag).matchesExactGET(transportErr.Request) {
		return false
	}
	for _, diagnostic := range transportErr.Errors {
		if diagnostic.Code != transport.ManifestUnknownErrorCode {
			return false
		}
	}
	return true
}

// getSignatureReferenceFromOCIImage resolves imageRef and returns where its
// cosign signatures live together with the artifact identity they must bind
// to — see signatureTarget.
func getSignatureReferenceFromOCIImage(
	ctx context.Context, imageRef string, keychain authn.Keychain,
) (signatureTarget, error) {
	return getSignatureReferenceFromOCIImageMode(ctx, imageRef, keychain, false)
}

func getSignatureReferenceFromOCIImageStrict(
	ctx context.Context, imageRef string, keychain authn.Keychain,
) (signatureTarget, error) {
	return getSignatureReferenceFromOCIImageMode(ctx, imageRef, keychain, true)
}

func getSignatureReferenceFromOCIImageMode(
	ctx context.Context, imageRef string, keychain authn.Keychain, strict bool,
) (signatureTarget, error) {
	// 0. Get the auth options
	opts := []remote.Option{remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx)}

	// 1. Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return signatureTarget{}, fmt.Errorf("error parsing image reference: %w", err)
	}
	if strict {
		budget := newResponseBodyBudget(MaxAttestationsBytesLimit, "artifact manifest response")
		opts = append(opts, remote.WithTransport(newStrictResponseTransport(
			budget, manifestRequestTarget(ref))))
	}

	// 2. Get the image descriptor
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return signatureTarget{}, fmt.Errorf("error getting image descriptor: %w", err)
	}

	// 3. Construct the signature reference - sha256-<hash>.sig
	repo := ref.Context()
	sigTag := repo.Tag(fmt.Sprint(desc.Digest.Algorithm, "-", desc.Digest.Hex, ".sig"))

	// 4. Return the tag together with the resolved artifact identity, so the
	// caller binds signatures to the digest this same lookup produced rather
	// than re-resolving a mutable reference.
	return signatureTarget{sigTag: sigTag, artifactDigest: desc.Digest, repo: repo}, nil
}

// getSimpleSigningLayersFromSignatureManifest returns the identity and issuer from the certificate
func getSimpleSigningLayersFromSignatureManifest(
	ctx context.Context, manifestRef string, keychain authn.Keychain,
) ([]v1.Descriptor, error) {
	craneOpts := []crane.Option{crane.WithAuthFromKeychain(keychain), crane.WithContext(ctx)}
	// Get the manifest of the signature
	mf, err := crane.Manifest(manifestRef, craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}

	// Parse the manifest
	r := io.LimitReader(bytes.NewReader(mf), MaxAttestationsBytesLimit)
	manifest, err := v1.ParseManifest(r)
	if err != nil {
		return nil, fmt.Errorf("error parsing signature manifest: %w", err)
	}

	// Loop through its layers and extract the simple signing layers
	var results []v1.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == MediaTypeCosignSimpleSigningV1JSON {
			// We found a simple signing layer, store and return it even if we may fail to parse it later
			results = append(results, layer)
		}
	}

	// Return the results - we may not have found any simple signing layers, but we still return the results
	return results, nil
}

func getSimpleSigningLayersFromSignatureTargetStrict(
	ctx context.Context,
	target signatureTarget,
	keychain authn.Keychain,
) ([]v1.Descriptor, error) {
	budget := newResponseBodyBudget(MaxAttestationsBytesLimit, "cosign signature manifest response")
	desc, err := remote.Get(
		target.sigTag,
		remote.WithAuthFromKeychain(keychain),
		remote.WithContext(ctx),
		remote.WithTransport(newStrictResponseTransport(
			budget, manifestRequestTarget(target.sigTag))),
	)
	if err != nil {
		return nil, fmt.Errorf("error getting signature manifest: %w", err)
	}
	if isImageIndexMediaType(desc.MediaType) {
		return nil, bundleSetIncompletef(
			"cosign signature tag %s is an image index; strict retrieval cannot select one child",
			target.sigTag.Name())
	}

	manifest, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return nil, fmt.Errorf("error parsing signature manifest: %w", err)
	}
	var results []v1.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == MediaTypeCosignSimpleSigningV1JSON {
			results = append(results, layer)
		}
	}
	return results, nil
}

// getBundleVerificationMaterial returns the bundle verification material from the simple signing layer
func getBundleVerificationMaterial(manifestLayer v1.Descriptor) (
	*protobundle.VerificationMaterial, error) {
	// 1. Classify the layout by certificate annotation PRESENCE. A layer
	// without one is the classic key-signed cosign layout ("cosign sign
	// --key"): the only verification material is the signature itself, and
	// trust is established by the verifier supplying the public key. A
	// certificate annotation that is present but malformed must remain an
	// error — the annotations are registry-supplied (attacker-controlled),
	// and a corrupt keyless layer must not be reclassified as key-signed.
	if manifestLayer.Annotations["dev.sigstore.cosign/certificate"] == "" {
		if !hasCosignSignatureAnnotation(manifestLayer) {
			return nil, errors.New("layer carries neither certificate nor signature annotation")
		}
		return &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{Hint: keySignedPublicKeyHint},
			},
		}, nil
	}
	signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting signing certificate: %w", err)
	}

	// 2. Get the transparency log entries, when present. A certificate-bearing
	// signature is not required to carry one — e.g. a Fulcio deployment run
	// without a paired transparency log — so an absent bundle annotation
	// means "no tlog entry", the same way an absent certificate annotation
	// means "key-signed" above. Calling getVerificationMaterialTlogEntries
	// unconditionally here would fail to unmarshal the empty annotation and
	// discard an otherwise valid certificate-only layer entirely.
	var tlogEntries []*protorekor.TransparencyLogEntry
	if manifestLayer.Annotations["dev.sigstore.cosign/bundle"] != "" {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}
	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   signingCert,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: nil,
	}, nil
}

// keySignedPublicKeyHint marks a reconstructed bundle as originating from
// the key-signed cosign layout: the stored bundle carries no key material
// itself, so offline re-verification requires the caller to supply the
// public key (VerifyBundleOfflineWithKey).
const keySignedPublicKeyHint = "cosign-keypair"

// hasCosignSignatureAnnotation reports whether the simple signing layer
// carries a cosign signature annotation.
func hasCosignSignatureAnnotation(layer v1.Descriptor) bool {
	return layer.Annotations["dev.cosignproject.cosign/signature"] != ""
}

// getVerificationMaterialX509CertificateChain returns the verification material X509 certificate chain from the
// simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer v1.Descriptor) (
	*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations["dev.sigstore.cosign/certificate"]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// getVerificationMaterialTlogEntries returns the verification material transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer v1.Descriptor) (
	[]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation
	bun := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	// 2. Get the log index, log ID, integrated time, signed entry timestamp and body.
	// Every assertion is two-valued: the annotation is registry-supplied
	// (attacker-controlled) data, and a malformed shape must be an error,
	// never a panic.
	payload, ok := jsonData["Payload"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("error getting Payload")
	}
	logIndex, ok := payload["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	logIndexInt64 := int64(logIndex)
	li, ok := payload["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := payload["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}
	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := payload["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}
	apiVersion, ok := jsonData["apiVersion"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting apiVersion")
	}
	kind, ok := jsonData["kind"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting kind")
	}
	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: logIndexInt64,
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple signing layer
func getBundleMsgSignature(simpleSigningLayer v1.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch simpleSigningLayer.Digest.Algorithm {
	case DigestAlgorithmSHA256:
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", simpleSigningLayer.Digest.Algorithm)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Hex)
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations["dev.cosignproject.cosign/signature"]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}

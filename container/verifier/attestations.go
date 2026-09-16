// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	containerdigest "github.com/opencontainers/go-digest"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// maxSigstoreReferrers bounds the registry work caused by a single referrers
// index in strict mode. Descriptors with a non-Sigstore artifact type are not
// counted; ambiguous descriptors are, because deciding whether they carry a
// bundle requires fetching them.
const maxSigstoreReferrers = 32

// bundleFromAttestation retrieves the attestation bundles from the image reference. Note that the attestation
// bundles are stored as OCI image references. The function uses the referrers API to get the attestation. GitHub supports
// discovering the attestations via their API, but this is not supported here for now.
func bundleFromAttestation(ctx context.Context, imageRef string, keychain authn.Keychain) ([]sigstoreBundle, error) {
	target, err := getSignatureReferenceFromOCIImage(ctx, imageRef, keychain)
	if err != nil {
		return nil, err
	}
	return bundleFromAttestationTarget(ctx, target, keychain, false)
}

// bundleFromAttestationTarget retrieves referrer bundles for an
// already-resolved artifact. Strict mode reports any operational failure or
// work-limit truncation as ErrBundleSetIncomplete, while material that was
// fully fetched but is malformed remains an unusable/rejected bundle.
func bundleFromAttestationTarget(
	ctx context.Context,
	target signatureTarget,
	keychain authn.Keychain,
	strict bool,
) ([]sigstoreBundle, error) {
	opts := []remote.Option{remote.WithAuthFromKeychain(keychain), remote.WithContext(ctx)}
	digestByte, err := hex.DecodeString(target.artifactDigest.Hex)
	if err != nil {
		return nil, err
	}

	refManifest, err := getReferrersManifest(target, opts, strict)
	if err != nil {
		return nil, err
	}
	if err := checkReferrerLimit(refManifest.Manifests, strict); err != nil {
		return nil, err
	}

	digestAlgo := containerdigest.Canonical.String()
	if strict {
		digestAlgo = target.artifactDigest.Algorithm
	}
	bundles := make([]sigstoreBundle, 0, len(refManifest.Manifests))
	var budget *referrerRetrievalBudget
	if strict {
		budget = &referrerRetrievalBudget{
			manifestResponses: newResponseBodyBudget(
				MaxAttestationsBytesLimit, "aggregate referrer manifest responses"),
			bundleBytes: MaxAttestationsBytesLimit,
		}
	}
	for _, refDesc := range refManifest.Manifests {
		b, err := bundleFromReferrer(target, refDesc, opts, strict, budget)
		if err != nil {
			return nil, err
		}
		if b == nil {
			continue
		}
		bundles = append(bundles, sigstoreBundle{
			bundle:      b,
			digestBytes: digestByte,
			digestAlgo:  digestAlgo,
		})
	}
	if len(bundles) == 0 {
		return nil, ErrProvenanceNotFoundOrIncomplete
	}
	return bundles, nil
}

type referrerRetrievalBudget struct {
	manifestResponses *responseBodyBudget
	bundleBytes       int64
}

func getReferrersManifest(
	target signatureTarget,
	opts []remote.Option,
	strict bool,
) (*v1.IndexManifest, error) {
	digest := target.repo.Digest(target.artifactDigest.String())
	referrerOpts, discovery := referrerDiscoveryOptions(digest, opts, strict)
	if strict {
		// Fetch the fallback tag ourselves. remote.Referrers turns every 404
		// from that request into an empty index, including redirected and
		// authentication failures that strict retrieval must preserve.
		referrerOpts = append(referrerOpts, remote.WithReferrersTagFallback(false))
	}
	referrers, err := remote.Referrers(digest, referrerOpts...)
	if strict {
		if failure := discovery.failure.Load(); failure != nil {
			return nil, bundleSetIncompleteBecause(failure, "reading referrers index")
		}
		if err != nil && discovery.fallback.Load() {
			return getReferrersFallbackManifest(digest, referrerOpts)
		}
	}
	if err != nil {
		if strict {
			return nil, bundleSetIncompleteBecause(err, "reading referrers index")
		}
		return nil, fmt.Errorf("error getting referrers: %w, %s", ErrProvenanceNotFoundOrIncomplete, err.Error())
	}
	if discovery != nil && discovery.pagination.Load() {
		return nil, bundleSetIncompletef("referrers response is paginated")
	}
	refManifest, err := referrers.IndexManifest()
	if err != nil {
		if strict {
			return nil, bundleSetIncompleteBecause(err, "parsing referrers index")
		}
		return nil, fmt.Errorf("error getting referrers manifest: %w, %s", ErrProvenanceNotFoundOrIncomplete, err.Error())
	}
	return refManifest, nil
}

func getReferrersFallbackManifest(
	digest name.Digest,
	opts []remote.Option,
) (*v1.IndexManifest, error) {
	fallbackTag := digest.Context().Tag(strings.Replace(digest.DigestStr(), ":", "-", 1))
	desc, err := remote.Get(fallbackTag, opts...)
	if err != nil {
		if isManifestNotFound(err, fallbackTag) {
			return &v1.IndexManifest{}, nil
		}
		return nil, bundleSetIncompleteBecause(err, "reading referrers fallback index")
	}
	if !isImageIndexMediaType(desc.MediaType) {
		return nil, bundleSetIncompletef(
			"referrers fallback tag %s has media type %s, not an image index",
			fallbackTag.Name(), desc.MediaType)
	}
	manifest, err := v1.ParseIndexManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return nil, bundleSetIncompleteBecause(err, "parsing referrers fallback index")
	}
	return manifest, nil
}

type referrerDiscoveryMonitor struct {
	pagination      atomic.Bool
	fallback        atomic.Bool
	failure         atomic.Pointer[transport.Error]
	inner           http.RoundTripper
	referrersTarget registryRequestTarget
}

func (d *referrerDiscoveryMonitor) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := d.inner.RoundTrip(req)
	if err != nil || !d.referrersTarget.matchesGET(req) {
		return resp, err
	}
	if resp.StatusCode == http.StatusOK &&
		resp.Header.Get("Content-Type") == string(types.OCIImageIndex) {
		if resp.Header.Get("Link") != "" {
			d.pagination.Store(true)
		}
		return resp, nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotAcceptable {
		return resp, nil
	}
	if d.referrersTarget.matchesExactGET(req) {
		d.fallback.Store(true)
	} else {
		d.failure.CompareAndSwap(nil, &transport.Error{StatusCode: resp.StatusCode, Request: req})
	}
	return resp, nil
}

func referrerDiscoveryOptions(
	digest name.Digest,
	opts []remote.Option,
	strict bool,
) ([]remote.Option, *referrerDiscoveryMonitor) {
	if !strict {
		return opts, nil
	}
	referrersTarget := referrersRequestTarget(digest)
	fallbackTag := digest.Context().Tag(strings.Replace(digest.DigestStr(), ":", "-", 1))
	limiter := newStrictResponseTransport(
		newResponseBodyBudget(MaxAttestationsBytesLimit, "referrers discovery response"),
		referrersTarget,
		indexManifestRequestTarget(fallbackTag),
	)
	detector := &referrerDiscoveryMonitor{
		inner:           limiter,
		referrersTarget: referrersTarget,
	}
	strictOpts := make([]remote.Option, 0, len(opts)+1)
	strictOpts = append(strictOpts, opts...)
	strictOpts = append(strictOpts, remote.WithTransport(detector))
	return strictOpts, detector
}

func checkReferrerLimit(referrers []v1.Descriptor, strict bool) error {
	if !strict {
		return nil
	}
	potentiallyRelevant, err := validateReferrerCandidateManifests(referrers)
	if err != nil {
		return err
	}
	if potentiallyRelevant <= maxSigstoreReferrers {
		return nil
	}
	return bundleSetIncompletef(
		"referrers index has %d potentially relevant bundles; limit is %d",
		potentiallyRelevant, maxSigstoreReferrers)
}

func validateReferrerCandidateManifests(referrers []v1.Descriptor) (int, error) {
	potentiallyRelevant := 0
	var totalSize int64
	for _, refDesc := range referrers {
		if !isPotentiallySigstoreReferrer(refDesc) {
			continue
		}
		potentiallyRelevant++
		if refDesc.Size <= 0 {
			return 0, bundleSetIncompletef(
				"referrer %s has invalid declared manifest size %d",
				refDesc.Digest.String(), refDesc.Size)
		}
		if refDesc.Size > MaxAttestationsBytesLimit-totalSize {
			return 0, bundleSetIncompletef(
				"aggregate declared referrer manifest size exceeds the retrieval limit")
		}
		totalSize += refDesc.Size
	}
	return potentiallyRelevant, nil
}

func bundleFromReferrer(
	target signatureTarget,
	refDesc v1.Descriptor,
	opts []remote.Option,
	strict bool,
	budget *referrerRetrievalBudget,
) (*bundle.Bundle, error) {
	if !isPotentiallySigstoreReferrer(refDesc) {
		return nil, nil
	}
	refImg, err := getReferrerImage(target, refDesc, opts, strict, budget)
	if err != nil {
		return nil, handleReferrerAcquisitionError(strict, "getting referrer image", refDesc, err)
	}
	if !hasSigstoreBundlePrefix(refDesc.ArtifactType) {
		isBundle, inspectErr := inspectSigstoreBundle(refImg)
		if inspectErr != nil {
			return nil, handleReferrerAcquisitionError(strict, "inspecting referrer", refDesc, inspectErr)
		}
		if !isBundle {
			return nil, nil
		}
	}
	readBudget := MaxAttestationsBytesLimit
	if strict {
		readBudget = budget.bundleBytes
	}
	b, bytesRead, err := extractBundleFromImage(refImg, strict, readBudget)
	if strict {
		budget.bundleBytes -= bytesRead
	}
	if err != nil {
		if strict && errors.Is(err, ErrBundleSetIncomplete) {
			return nil, err
		}
		slog.Debug("error extracting bundle from referrer",
			"referrer_digest", refDesc.Digest.String(), "error", err)
		return nil, nil
	}
	return b, nil
}

func getReferrerImage(
	target signatureTarget,
	refDesc v1.Descriptor,
	opts []remote.Option,
	strict bool,
	budget *referrerRetrievalBudget,
) (v1.Image, error) {
	ref := target.repo.Digest(refDesc.Digest.String())
	if !strict {
		return remote.Image(ref, opts...)
	}

	strictOpts := make([]remote.Option, 0, len(opts)+1)
	strictOpts = append(strictOpts, opts...)
	strictOpts = append(strictOpts, remote.WithTransport(newStrictResponseTransport(
		budget.manifestResponses, manifestRequestTarget(ref))))
	desc, err := remote.Get(ref, strictOpts...)
	if err != nil {
		return nil, err
	}
	actualSize := int64(len(desc.Manifest))
	if desc.Size != refDesc.Size || actualSize != refDesc.Size {
		return nil, bundleSetIncompletef(
			"referrer %s manifest size mismatch: index=%d response=%d body=%d",
			refDesc.Digest.String(), refDesc.Size, desc.Size, actualSize)
	}
	if isImageIndexMediaType(refDesc.MediaType) || isImageIndexMediaType(desc.MediaType) {
		return nil, bundleSetIncompletef(
			"referrer %s is an image index; strict retrieval cannot select one child",
			refDesc.Digest.String())
	}
	return desc.Image()
}

func isImageIndexMediaType(mediaType types.MediaType) bool {
	return mediaType == types.OCIImageIndex || mediaType == types.DockerManifestList
}

func isPotentiallySigstoreReferrer(refDesc v1.Descriptor) bool {
	return hasSigstoreBundlePrefix(refDesc.ArtifactType) ||
		refDesc.ArtifactType == MediaTypeOCIEmptyV1JSON || refDesc.ArtifactType == ""
}

func handleReferrerAcquisitionError(strict bool, operation string, refDesc v1.Descriptor, err error) error {
	if strict {
		if errors.Is(err, ErrBundleSetIncomplete) {
			return err
		}
		return bundleSetIncompleteBecause(err, "%s %s", operation, refDesc.Digest.String())
	}
	slog.Debug("error "+operation, "referrer_digest", refDesc.Digest.String(), "error", err)
	return nil
}

// extractBundleFromImage reads and parses a sigstore bundle from the first layer of an OCI image.
func extractBundleFromImage(img v1.Image, strict bool, readBudget int64) (*bundle.Bundle, int64, error) {
	layers, err := img.Layers()
	if err != nil {
		if strict {
			return nil, 0, bundleSetIncompleteBecause(err, "getting referrer layers")
		}
		return nil, 0, fmt.Errorf("error getting referrer layers: %w", err)
	}
	readLimit, err := referrerLayerReadLimit(len(layers), strict, readBudget)
	if err != nil {
		return nil, 0, err
	}
	layer0, err := layers[0].Uncompressed()
	if err != nil {
		if strict {
			return nil, 0, bundleSetIncompleteBecause(err, "opening referrer layer")
		}
		return nil, 0, fmt.Errorf("error uncompressing referrer layer: %w", err)
	}
	defer func() { _ = layer0.Close() }()
	bundleBytes, err := io.ReadAll(io.LimitReader(layer0, readLimit))
	if err != nil {
		if strict {
			return nil, int64(len(bundleBytes)), bundleSetIncompleteBecause(err, "reading referrer layer")
		}
		return nil, int64(len(bundleBytes)), fmt.Errorf("error reading referrer layer: %w", err)
	}
	bytesRead := int64(len(bundleBytes))
	if strict && bytesRead > readBudget {
		return nil, bytesRead, bundleSetIncompletef("aggregate referrer bundle byte limit is exceeded")
	}
	b := &bundle.Bundle{}
	if err = b.UnmarshalJSON(bundleBytes); err != nil {
		return nil, bytesRead, fmt.Errorf("error unmarshalling bundle: %w", err)
	}
	return b, bytesRead, nil
}

func referrerLayerReadLimit(layerCount int, strict bool, readBudget int64) (int64, error) {
	if layerCount == 0 {
		return 0, fmt.Errorf("referrer has no layers")
	}
	if strict && layerCount > 1 {
		return 0, bundleSetIncompletef(
			"referrer has %d layers; strict retrieval requires exactly one", layerCount)
	}
	if strict && readBudget <= 0 {
		return 0, bundleSetIncompletef("aggregate referrer bundle byte limit is exhausted")
	}

	// Cap the read: the layer comes from the registry (untrusted) and the
	// signature-manifest path enforces the same limit.
	readLimit := min(readBudget, MaxAttestationsBytesLimit)
	if strict {
		// Read one bounded byte beyond the accepted limit so strict retrieval
		// can distinguish truncation from completely read malformed content.
		readLimit++
	}
	return readLimit, nil
}

// isSigstoreBundle inspects the actual manifest of a referrer image to
// determine whether it is a sigstore bundle. This is used as a fallback when
// the referrer index descriptor's artifactType is ambiguous (e.g. GHCR sets it
// to "application/vnd.oci.empty.v1+json" due to google/go-containerregistry#1997).
func isSigstoreBundle(img v1.Image) bool {
	isBundle, err := inspectSigstoreBundle(img)
	if err != nil {
		slog.Debug("error fetching manifest for sigstore bundle check", "error", err)
		return false
	}
	return isBundle
}

// inspectSigstoreBundle is the error-preserving form of isSigstoreBundle.
// Strict retrieval needs the error to distinguish an operationally
// incomplete inspection from fully-read malformed material.
func inspectSigstoreBundle(img v1.Image) (bool, error) {
	mf, err := img.Manifest()
	if err != nil {
		return false, err
	}

	// Check the config descriptor's artifactType (set by cosign v2+ when using OCI 1.1 referrers)
	if hasSigstoreBundlePrefix(mf.Config.ArtifactType) {
		return true, nil
	}

	// Check layer media types as a final fallback
	for _, layer := range mf.Layers {
		if hasSigstoreBundlePrefix(string(layer.MediaType)) {
			return true, nil
		}
	}

	return false, nil
}

// hasSigstoreBundlePrefix checks if a media/artifact type string indicates a sigstore bundle.
func hasSigstoreBundlePrefix(s string) bool {
	return strings.HasPrefix(s, "application/vnd.dev.sigstore.bundle")
}

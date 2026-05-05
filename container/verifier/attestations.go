// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	containerdigest "github.com/opencontainers/go-digest"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// bundleFromAttestation retrieves the attestation bundles from the image reference. Note that the attestation
// bundles are stored as OCI image references. The function uses the referrers API to get the attestation. GitHub supports
// discovering the attestations via their API, but this is not supported here for now.
func bundleFromAttestation(imageRef string, keychain authn.Keychain) ([]sigstoreBundle, error) {
	var bundles []sigstoreBundle

	// Get the auth options
	opts := []remote.Option{remote.WithAuthFromKeychain(keychain)}

	// Get the image reference
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("error parsing image reference: %w", err)
	}

	// Get the image descriptor
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("error getting image descriptor: %w", err)
	}

	// Get the digest
	digest := ref.Context().Digest(desc.Digest.String())

	// Get the digest in bytes
	digestByte, err := hex.DecodeString(desc.Digest.Hex)
	if err != nil {
		return nil, err
	}

	// Use the referrers API to get the attestation reference
	referrers, err := remote.Referrers(digest, opts...)
	if err != nil {
		return nil, fmt.Errorf("error getting referrers: %w, %s", ErrProvenanceNotFoundOrIncomplete, err.Error())
	}

	refManifest, err := referrers.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("error getting referrers manifest: %w, %s", ErrProvenanceNotFoundOrIncomplete, err.Error())
	}

	// Loop through all available attestations and extract the bundle
	for _, refDesc := range refManifest.Manifests {
		// Fast path: skip referrers that are clearly not sigstore bundles without
		// fetching the manifest. Only do a deep inspection when the artifact type
		// is ambiguous (empty or "application/vnd.oci.empty.v1+json"), which
		// happens due to a go-containerregistry bug (google/go-containerregistry#1997)
		// where the referrers fallback tag doesn't propagate the inner manifest's
		// artifactType.
		if !hasSigstoreBundlePrefix(refDesc.ArtifactType) &&
			refDesc.ArtifactType != MediaTypeOCIEmptyV1JSON &&
			refDesc.ArtifactType != "" {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(refDesc.Digest.String()), opts...)
		if err != nil {
			slog.Debug("error getting referrer image", "error", err)
			continue
		}

		// When the index descriptor's artifactType is ambiguous, inspect the
		// actual manifest to determine whether this is a sigstore bundle.
		if !hasSigstoreBundlePrefix(refDesc.ArtifactType) && !isSigstoreBundle(refImg) {
			continue
		}

		b, err := extractBundleFromImage(refImg)
		if err != nil {
			slog.Debug("error extracting bundle from referrer", "error", err)
			continue
		}

		bundles = append(bundles, sigstoreBundle{
			bundle:      b,
			digestBytes: digestByte,
			digestAlgo:  containerdigest.Canonical.String(),
		})
	}
	if len(bundles) == 0 {
		return nil, ErrProvenanceNotFoundOrIncomplete
	}
	return bundles, nil
}

// extractBundleFromImage reads and parses a sigstore bundle from the first layer of an OCI image.
func extractBundleFromImage(img v1.Image) (*bundle.Bundle, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("error getting referrer layers: %w", err)
	}
	if len(layers) == 0 {
		return nil, fmt.Errorf("referrer has no layers")
	}
	layer0, err := layers[0].Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("error uncompressing referrer layer: %w", err)
	}
	bundleBytes, err := io.ReadAll(layer0)
	if err != nil {
		return nil, fmt.Errorf("error reading referrer layer: %w", err)
	}
	b := &bundle.Bundle{}
	if err = b.UnmarshalJSON(bundleBytes); err != nil {
		return nil, fmt.Errorf("error unmarshalling bundle: %w", err)
	}
	return b, nil
}

// isSigstoreBundle inspects the actual manifest of a referrer image to
// determine whether it is a sigstore bundle. This is used as a fallback when
// the referrer index descriptor's artifactType is ambiguous (e.g. GHCR sets it
// to "application/vnd.oci.empty.v1+json" due to google/go-containerregistry#1997).
func isSigstoreBundle(img v1.Image) bool {
	mf, err := img.Manifest()
	if err != nil {
		slog.Debug("error fetching manifest for sigstore bundle check", "error", err)
		return false
	}

	// Check the config descriptor's artifactType (set by cosign v2+ when using OCI 1.1 referrers)
	if hasSigstoreBundlePrefix(mf.Config.ArtifactType) {
		return true
	}

	// Check layer media types as a final fallback
	for _, layer := range mf.Layers {
		if hasSigstoreBundlePrefix(string(layer.MediaType)) {
			return true
		}
	}

	return false
}

// hasSigstoreBundlePrefix checks if a media/artifact type string indicates a sigstore bundle.
func hasSigstoreBundlePrefix(s string) bool {
	return strings.HasPrefix(s, "application/vnd.dev.sigstore.bundle")
}

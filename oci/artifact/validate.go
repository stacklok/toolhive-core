// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
)

// MaxManifestSize is the maximum size of a manifest (1MB).
const MaxManifestSize int64 = 1 * 1024 * 1024

// MaxBlobSize is the maximum size of a blob (100MB).
const MaxBlobSize int64 = 100 * 1024 * 1024

// maxIndexManifests is the maximum number of manifests in an image index.
const maxIndexManifests = 32

// maxManifestLayers is the maximum number of layers in a manifest.
const maxManifestLayers = 64

// Compile-time interface check.
var _ oras.Target = (*ValidatingTarget)(nil)

// ValidatingTarget wraps an oras.Target to enforce size and count limits
// on pushed content. This prevents OOM and resource exhaustion from
// malicious registries during pull operations.
type ValidatingTarget struct {
	inner oras.Target
}

// NewValidatingTarget wraps an oras.Target with size and structure validation
// applied on every Push.
func NewValidatingTarget(inner oras.Target) *ValidatingTarget {
	return &ValidatingTarget{inner: inner}
}

// Fetch delegates to the inner target.
func (v *ValidatingTarget) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	return v.inner.Fetch(ctx, target)
}

// Exists delegates to the inner target.
func (v *ValidatingTarget) Exists(ctx context.Context, target ocispec.Descriptor) (bool, error) {
	return v.inner.Exists(ctx, target)
}

// Resolve delegates to the inner target.
func (v *ValidatingTarget) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return v.inner.Resolve(ctx, reference)
}

// Tag delegates to the inner target.
func (v *ValidatingTarget) Tag(ctx context.Context, desc ocispec.Descriptor, reference string) error {
	return v.inner.Tag(ctx, desc, reference)
}

// Push validates size and structure limits before delegating to the inner target.
func (v *ValidatingTarget) Push(ctx context.Context, desc ocispec.Descriptor, content io.Reader) error {
	maxSize := MaxBlobSize
	if isManifestMediaType(desc.MediaType) {
		maxSize = MaxManifestSize
	}

	if desc.Size < 0 {
		return fmt.Errorf("invalid negative content size %d", desc.Size)
	}
	if desc.Size > maxSize {
		return fmt.Errorf(
			"content size %d exceeds maximum allowed size %d for media type %q",
			desc.Size, maxSize, desc.MediaType,
		)
	}

	// Read with a limit to defend against lying descriptors
	limitedReader := io.LimitReader(content, maxSize+1)
	data, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("reading content: %w", err)
	}

	if int64(len(data)) > maxSize {
		return fmt.Errorf(
			"actual content size exceeds maximum allowed size %d for media type %q",
			maxSize, desc.MediaType,
		)
	}

	// Verify digest integrity — defense-in-depth against a lying registry
	actual := digest.FromBytes(data)
	if actual != desc.Digest {
		return fmt.Errorf("digest mismatch: expected %s, got %s", desc.Digest, actual)
	}

	// Validate manifest/index structure limits
	if err := validateManifestCounts(desc.MediaType, data); err != nil {
		return err
	}

	return v.inner.Push(ctx, desc, bytes.NewReader(data))
}

// validateManifestCounts checks layer/manifest counts for resource exhaustion prevention.
//
// It only inspects media types it recognizes (image index and image manifest).
// For any other media type it returns nil without examining the data. A nil
// return therefore means "no count violation was detected", not "this manifest
// is safe" — callers must not treat a nil return as a general safety guarantee.
func validateManifestCounts(mediaType string, data []byte) error {
	switch mediaType {
	case ocispec.MediaTypeImageIndex:
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return fmt.Errorf("parsing index: %w", err)
		}
		if len(index.Manifests) > maxIndexManifests {
			return fmt.Errorf(
				"index has %d manifests, exceeds maximum of %d",
				len(index.Manifests), maxIndexManifests,
			)
		}
	case ocispec.MediaTypeImageManifest:
		var manifest ocispec.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return fmt.Errorf("parsing manifest: %w", err)
		}
		if len(manifest.Layers) > maxManifestLayers {
			return fmt.Errorf(
				"manifest has %d layers, exceeds maximum of %d",
				len(manifest.Layers), maxManifestLayers,
			)
		}
	}
	return nil
}

// isManifestMediaType returns true if the media type is a manifest or index type.
func isManifestMediaType(mediaType string) bool {
	switch mediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex,
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json":
		return true
	default:
		return false
	}
}

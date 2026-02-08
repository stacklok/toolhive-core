// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
)

// MaxManifestSize is the maximum size of a manifest (1MB).
const MaxManifestSize int64 = 1 * 1024 * 1024

// MaxBlobSize is the maximum size of a blob (100MB).
const MaxBlobSize int64 = 100 * 1024 * 1024

// maxIndexManifests is the maximum number of manifests in an image index.
const maxIndexManifests = 32

// maxManifestLayers is the maximum number of layers in a manifest.
const maxManifestLayers = 64

// Compile-time interface checks.
var (
	_ RegistryClient = (*Registry)(nil)
	_ oras.Target    = (*validatingTarget)(nil)
)

// Registry provides operations for pushing and pulling skills from OCI registries.
type Registry struct {
	credStore credentials.Store
	plainHTTP bool

	// newTarget creates an oras.Target for the given reference.
	// Defaults to creating an authenticated remote.Repository.
	// Override in tests to inject an in-memory store.
	newTarget func(ref registry.Reference) (oras.Target, error)
}

// RegistryOption configures a Registry.
type RegistryOption func(*Registry)

// WithPlainHTTP configures whether the registry client uses plain HTTP (insecure) connections.
func WithPlainHTTP(enabled bool) RegistryOption {
	return func(r *Registry) {
		r.plainHTTP = enabled
	}
}

// WithCredentialStore sets a custom credential store for registry authentication.
// If not provided, the default Docker credential store is used.
func WithCredentialStore(store credentials.Store) RegistryOption {
	return func(r *Registry) {
		r.credStore = store
	}
}

// NewRegistry creates a new registry client with the given options.
// By default it uses the Docker credential store for authentication.
func NewRegistry(opts ...RegistryOption) (*Registry, error) {
	r := &Registry{}

	for _, opt := range opts {
		opt(r)
	}

	if r.credStore == nil {
		credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating credential store: %w", err)
		}
		r.credStore = credStore
	}

	if r.newTarget == nil {
		r.newTarget = r.defaultNewTarget
	}

	return r, nil
}

// Push pushes a skill artifact from the local store to a remote registry.
// The digest can be either an index digest or a manifest digest.
func (r *Registry) Push(ctx context.Context, store *Store, artifactDigest digest.Digest, ref string) error {
	parsedRef, err := parseReference(ref)
	if err != nil {
		return err
	}

	// Resolve the artifact to get its full descriptor from the OCI store.
	desc, err := store.Target().Resolve(ctx, artifactDigest.String())
	if err != nil {
		return fmt.Errorf("resolving artifact descriptor: %w", err)
	}

	target, err := r.newTarget(parsedRef)
	if err != nil {
		return fmt.Errorf("getting repository: %w", err)
	}

	// Copy the content graph (blobs → manifests → index) to the remote
	if err := oras.CopyGraph(ctx, store.Target(), target, desc, oras.DefaultCopyGraphOptions); err != nil {
		return fmt.Errorf("pushing to registry: %w", err)
	}

	// Tag on the remote with the requested reference
	if err := target.Tag(ctx, desc, parsedRef.Reference); err != nil {
		return fmt.Errorf("tagging remote: %w", err)
	}

	return nil
}

// Pull pulls a skill artifact from a remote registry to the local store.
// Returns the digest of the pulled artifact (index or manifest).
func (r *Registry) Pull(ctx context.Context, store *Store, ref string) (digest.Digest, error) {
	parsedRef, err := parseReference(ref)
	if err != nil {
		return "", err
	}

	target, err := r.newTarget(parsedRef)
	if err != nil {
		return "", fmt.Errorf("getting repository: %w", err)
	}

	validated := newValidatingTarget(store.Target())

	// Copy from remote to the validated local store
	desc, err := oras.Copy(
		ctx, target, parsedRef.Reference, validated, parsedRef.Reference, oras.DefaultCopyOptions,
	)
	if err != nil {
		return "", fmt.Errorf("pulling from registry: %w", err)
	}

	// oras.Copy already tagged with the short reference (parsedRef.Reference, e.g. "v1.0.0").
	// Additionally tag with the full OCI reference for local resolution.
	if err := store.Tag(ctx, desc.Digest, ref); err != nil {
		return "", fmt.Errorf("tagging locally: %w", err)
	}

	return desc.Digest, nil
}

// validatingTarget wraps an oras.Target to enforce size and count limits
// on pushed content. This prevents OOM and resource exhaustion from
// malicious registries during pull operations.
type validatingTarget struct {
	inner oras.Target
}

func newValidatingTarget(inner oras.Target) *validatingTarget {
	return &validatingTarget{inner: inner}
}

// Fetch delegates to the inner target.
func (v *validatingTarget) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	return v.inner.Fetch(ctx, target)
}

// Exists delegates to the inner target.
func (v *validatingTarget) Exists(ctx context.Context, target ocispec.Descriptor) (bool, error) {
	return v.inner.Exists(ctx, target)
}

// Resolve delegates to the inner target.
func (v *validatingTarget) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return v.inner.Resolve(ctx, reference)
}

// Tag delegates to the inner target.
func (v *validatingTarget) Tag(ctx context.Context, desc ocispec.Descriptor, reference string) error {
	return v.inner.Tag(ctx, desc, reference)
}

// Push validates size and structure limits before delegating to the inner target.
func (v *validatingTarget) Push(ctx context.Context, desc ocispec.Descriptor, content io.Reader) error {
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

// parseReference parses an OCI reference and validates it has a tag or digest.
func parseReference(ref string) (registry.Reference, error) {
	parsedRef, err := registry.ParseReference(ref)
	if err != nil {
		return registry.Reference{}, fmt.Errorf("parsing reference %q: %w", ref, err)
	}
	if parsedRef.Reference == "" {
		return registry.Reference{}, fmt.Errorf("reference %q must include a tag or digest", ref)
	}
	return parsedRef, nil
}

// defaultNewTarget creates a remote repository client for the given parsed reference.
func (r *Registry) defaultNewTarget(ref registry.Reference) (oras.Target, error) {
	repoPath := ref.Registry + "/" + ref.Repository

	repo, err := remote.NewRepository(repoPath)
	if err != nil {
		return nil, fmt.Errorf("creating repository for %q: %w", repoPath, err)
	}

	repo.Client = &auth.Client{
		Credential: credentials.Credential(r.credStore),
	}
	repo.PlainHTTP = r.plainHTTP

	return repo, nil
}

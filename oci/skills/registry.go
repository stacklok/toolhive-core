// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/errdef"
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
// Skill artifacts typically have 2-3 platforms; 32 is generous.
const maxIndexManifests = 32

// maxManifestLayers is the maximum number of layers in a manifest.
// Skill artifacts typically have 1 layer; 64 is generous.
const maxManifestLayers = 64

// Compile-time check that Registry implements RegistryClient.
var _ RegistryClient = (*Registry)(nil)

// registryTarget combines the ORAS interfaces needed for both push (Target) and pull (ReadOnlyTarget).
type registryTarget interface {
	oras.Target
}

// Registry provides operations for pushing and pulling skills from OCI registries.
type Registry struct {
	credStore credentials.Store
	plainHTTP bool // Use HTTP instead of HTTPS (insecure)

	// newTarget creates an oras.Target for the given reference.
	// Defaults to creating an authenticated remote.Repository.
	// Override in tests to inject an in-memory store.
	newTarget func(ref registry.Reference) (registryTarget, error)
}

// RegistryOption configures a Registry.
type RegistryOption func(*Registry)

// WithPlainHTTP configures whether the registry client uses plain HTTP (insecure) connections.
// When enabled, the client will use HTTP instead of HTTPS.
// This is useful for local development registries that don't have TLS.
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

	// Use Docker credential store if none was provided
	if r.credStore == nil {
		credStore, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating credential store: %w", err)
		}
		r.credStore = credStore
	}

	// Default to creating remote repositories
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

	// Check if this is an index or manifest
	isIndex, err := store.IsIndex(ctx, artifactDigest)
	if err != nil {
		return fmt.Errorf("checking artifact type: %w", err)
	}

	// Create in-memory store for the push operation
	memStore := memory.New()

	var tagDesc ocispec.Descriptor

	if isIndex {
		tagDesc, err = r.stageIndex(ctx, store, memStore, artifactDigest)
		if err != nil {
			return err
		}
	} else {
		tagDesc, err = r.stageManifest(ctx, store, memStore, artifactDigest)
		if err != nil {
			return err
		}
	}

	// Tag in memory store using just the tag/digest part
	if err := memStore.Tag(ctx, tagDesc, parsedRef.Reference); err != nil {
		return fmt.Errorf("tagging artifact: %w", err)
	}

	// Create remote target
	target, err := r.newTarget(parsedRef)
	if err != nil {
		return fmt.Errorf("getting repository: %w", err)
	}

	// Copy from memory store to remote
	_, err = oras.Copy(
		ctx, memStore, parsedRef.Reference, target, parsedRef.Reference, oras.DefaultCopyOptions,
	)
	if err != nil {
		return fmt.Errorf("pushing to registry: %w", err)
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

	// Create size-limited in-memory store to prevent OOM attacks.
	memStore := newSizeLimitedStore()

	// Copy from remote to memory store
	desc, err := oras.Copy(
		ctx, target, parsedRef.Reference, memStore, parsedRef.Reference, oras.DefaultCopyOptions,
	)
	if err != nil {
		return "", fmt.Errorf("pulling from registry: %w", err)
	}

	// Detect if this is an index or manifest.
	// Use the underlying memory.Store for read operations - size limits were
	// already enforced during the oras.Copy above via the sizeLimitedStore wrapper.
	if desc.MediaType == MediaTypeImageIndex {
		indexDigest, err := r.storeIndex(ctx, store, memStore.store, desc)
		if err != nil {
			return "", err
		}
		if err := store.Tag(ctx, indexDigest, ref); err != nil {
			return "", fmt.Errorf("tagging index locally: %w", err)
		}
		return indexDigest, nil
	}

	// Handle direct manifest (single-platform artifact)
	return r.storeManifestFromMemory(ctx, store, memStore.store, desc, ref)
}

// stageIndex stages an index and its referenced manifests/blobs to memory store.
func (r *Registry) stageIndex(
	ctx context.Context, store *Store, memStore *memory.Store, indexDigest digest.Digest,
) (ocispec.Descriptor, error) {
	index, err := store.GetIndex(ctx, indexDigest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("getting index: %w", err)
	}

	if len(index.Manifests) > maxIndexManifests {
		return ocispec.Descriptor{}, fmt.Errorf(
			"index has %d manifests, exceeds maximum of %d", len(index.Manifests), maxIndexManifests,
		)
	}

	indexBytes, err := store.GetManifest(ctx, indexDigest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("getting index bytes: %w", err)
	}

	// Stage manifests referenced by the index (deduplicate shared digests)
	stagedManifests := make(map[string]bool)
	for _, desc := range index.Manifests {
		if stagedManifests[desc.Digest] {
			continue
		}
		stagedManifests[desc.Digest] = true

		manifestDigest, err := digest.Parse(desc.Digest)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("parsing manifest digest: %w", err)
		}

		if _, err := r.stageManifest(ctx, store, memStore, manifestDigest); err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("staging manifest %s: %w", desc.Digest, err)
		}
	}

	// Stage the index itself
	indexDesc := ocispec.Descriptor{
		MediaType:    index.MediaType,
		Digest:       indexDigest,
		Size:         int64(len(indexBytes)),
		ArtifactType: index.ArtifactType,
		Annotations:  index.Annotations,
	}
	if err := memStore.Push(ctx, indexDesc, bytes.NewReader(indexBytes)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("staging index: %w", err)
	}

	return indexDesc, nil
}

// stageManifest stages a manifest and its blobs to memory store.
func (r *Registry) stageManifest(
	ctx context.Context, store *Store, memStore *memory.Store, manifestDigest digest.Digest,
) (ocispec.Descriptor, error) {
	manifestBytes, err := store.GetManifest(ctx, manifestDigest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("getting manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parsing manifest: %w", err)
	}

	if len(manifest.Layers) > maxManifestLayers {
		return ocispec.Descriptor{}, fmt.Errorf(
			"manifest has %d layers, exceeds maximum of %d", len(manifest.Layers), maxManifestLayers,
		)
	}

	if err := r.stageBlobs(ctx, store, memStore, &manifest); err != nil {
		return ocispec.Descriptor{}, err
	}

	manifestDesc := ocispec.Descriptor{
		MediaType:    manifest.MediaType,
		Digest:       manifestDigest,
		Size:         int64(len(manifestBytes)),
		ArtifactType: manifest.ArtifactType,
		Annotations:  manifest.Annotations,
	}
	if err := memStore.Push(ctx, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("staging manifest: %w", err)
	}

	return manifestDesc, nil
}

// stageBlobs stages config and layer blobs from local store to memory store.
// Blobs that already exist in the memory store are skipped (this happens when
// multiple platform manifests share the same blobs).
func (*Registry) stageBlobs(
	ctx context.Context, store *Store, memStore *memory.Store, manifest *ocispec.Manifest,
) error {
	configBytes, err := store.GetBlob(ctx, manifest.Config.Digest)
	if err != nil {
		return fmt.Errorf("getting config blob: %w", err)
	}
	configDesc := ocispec.Descriptor{
		MediaType: manifest.Config.MediaType,
		Digest:    manifest.Config.Digest,
		Size:      int64(len(configBytes)),
	}
	if err := memStore.Push(ctx, configDesc, bytes.NewReader(configBytes)); err != nil &&
		!errors.Is(err, errdef.ErrAlreadyExists) {
		return fmt.Errorf("staging config: %w", err)
	}

	for _, layer := range manifest.Layers {
		layerBytes, err := store.GetBlob(ctx, layer.Digest)
		if err != nil {
			return fmt.Errorf("getting layer blob: %w", err)
		}
		layerDesc := ocispec.Descriptor{
			MediaType: layer.MediaType,
			Digest:    layer.Digest,
			Size:      int64(len(layerBytes)),
		}
		if err := memStore.Push(ctx, layerDesc, bytes.NewReader(layerBytes)); err != nil &&
			!errors.Is(err, errdef.ErrAlreadyExists) {
			return fmt.Errorf("staging layer: %w", err)
		}
	}

	return nil
}

// storeIndex stores an index and its referenced content from memory to local store.
func (r *Registry) storeIndex(
	ctx context.Context, store *Store, memStore *memory.Store, desc ocispec.Descriptor,
) (digest.Digest, error) {
	indexReader, err := memStore.Fetch(ctx, desc)
	if err != nil {
		return "", fmt.Errorf("fetching index: %w", err)
	}

	// Defense-in-depth: re-enforce size limits even though sizeLimitedStore already checked
	limitedReader := io.LimitReader(indexReader, MaxManifestSize+1)
	indexBytes, err := io.ReadAll(limitedReader)
	if closeErr := indexReader.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return "", fmt.Errorf("reading index: %w", err)
	}

	if int64(len(indexBytes)) > MaxManifestSize {
		return "", fmt.Errorf("index exceeds maximum size of %d bytes", MaxManifestSize)
	}

	var index ImageIndex
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return "", fmt.Errorf("parsing index: %w", err)
	}

	if len(index.Manifests) > maxIndexManifests {
		return "", fmt.Errorf(
			"index has %d manifests, exceeds maximum of %d", len(index.Manifests), maxIndexManifests,
		)
	}

	// Store manifests referenced by the index
	storedManifests := make(map[string]bool)
	for _, manifestDesc := range index.Manifests {
		if storedManifests[manifestDesc.Digest] {
			continue
		}
		storedManifests[manifestDesc.Digest] = true

		manifestDigest, err := digest.Parse(manifestDesc.Digest)
		if err != nil {
			return "", fmt.Errorf("parsing manifest digest: %w", err)
		}

		ociDesc := ocispec.Descriptor{
			MediaType: manifestDesc.MediaType,
			Digest:    manifestDigest,
			Size:      manifestDesc.Size,
		}

		if _, err := r.storeManifestFromMemory(ctx, store, memStore, ociDesc, ""); err != nil {
			return "", fmt.Errorf("storing manifest %s: %w", manifestDesc.Digest, err)
		}
	}

	indexDigest, err := store.PutManifest(ctx, indexBytes)
	if err != nil {
		return "", fmt.Errorf("storing index: %w", err)
	}

	return indexDigest, nil
}

// storeManifestFromMemory stores a manifest and its blobs from memory to local store.
func (r *Registry) storeManifestFromMemory(
	ctx context.Context, store *Store, memStore *memory.Store, desc ocispec.Descriptor, ref string,
) (digest.Digest, error) {
	manifest, manifestBytes, err := r.fetchManifest(ctx, memStore, desc)
	if err != nil {
		return "", err
	}

	if err := r.storeBlobs(ctx, store, memStore, manifest); err != nil {
		return "", err
	}

	storedDigest, err := store.PutManifest(ctx, manifestBytes)
	if err != nil {
		return "", fmt.Errorf("storing manifest: %w", err)
	}

	if ref != "" {
		if err := store.Tag(ctx, storedDigest, ref); err != nil {
			return "", fmt.Errorf("tagging locally: %w", err)
		}
	}

	return storedDigest, nil
}

// fetchManifest fetches and parses a manifest from a memory store.
func (*Registry) fetchManifest(
	ctx context.Context, memStore *memory.Store, desc ocispec.Descriptor,
) (*ocispec.Manifest, []byte, error) {
	manifestReader, err := memStore.Fetch(ctx, desc)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching manifest: %w", err)
	}

	// Defense-in-depth: re-enforce size limits even though sizeLimitedStore already checked
	limitedReader := io.LimitReader(manifestReader, MaxManifestSize+1)
	manifestBytes, err := io.ReadAll(limitedReader)
	if closeErr := manifestReader.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading manifest: %w", err)
	}

	if int64(len(manifestBytes)) > MaxManifestSize {
		return nil, nil, fmt.Errorf("manifest exceeds maximum size of %d bytes", MaxManifestSize)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, nil, fmt.Errorf("parsing manifest: %w", err)
	}

	if len(manifest.Layers) > maxManifestLayers {
		return nil, nil, fmt.Errorf(
			"manifest has %d layers, exceeds maximum of %d", len(manifest.Layers), maxManifestLayers,
		)
	}

	return &manifest, manifestBytes, nil
}

// storeBlobs stores config and layer blobs from memory store to local store.
func (*Registry) storeBlobs(
	ctx context.Context, store *Store, memStore *memory.Store, manifest *ocispec.Manifest,
) error {
	if err := storeBlobFromMemory(ctx, store, memStore, manifest.Config); err != nil {
		return fmt.Errorf("storing config: %w", err)
	}

	for _, layer := range manifest.Layers {
		if err := storeBlobFromMemory(ctx, store, memStore, layer); err != nil {
			return fmt.Errorf("storing layer: %w", err)
		}
	}

	return nil
}

// storeBlobFromMemory fetches a blob from memory store and stores it in local store.
func storeBlobFromMemory(
	ctx context.Context, store *Store, memStore *memory.Store, desc ocispec.Descriptor,
) error {
	reader, err := memStore.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("fetching blob: %w", err)
	}

	limitedReader := io.LimitReader(reader, MaxBlobSize+1)
	data, err := io.ReadAll(limitedReader)
	if closeErr := reader.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("reading blob: %w", err)
	}

	if int64(len(data)) > MaxBlobSize {
		return fmt.Errorf("blob exceeds maximum size of %d bytes", MaxBlobSize)
	}

	if _, err := store.PutBlob(ctx, data); err != nil {
		return fmt.Errorf("storing blob: %w", err)
	}
	return nil
}

// sizeLimitedStore wraps a memory store to enforce size limits during Push operations.
// This prevents OOM attacks by rejecting oversized content before it's stored in memory.
// Uses explicit composition (not embedding) to avoid exposing unguarded methods.
type sizeLimitedStore struct {
	store *memory.Store
}

// newSizeLimitedStore creates a new size-limited store wrapper.
func newSizeLimitedStore() *sizeLimitedStore {
	return &sizeLimitedStore{store: memory.New()}
}

// Exists delegates to the underlying store.
func (s *sizeLimitedStore) Exists(ctx context.Context, target ocispec.Descriptor) (bool, error) {
	return s.store.Exists(ctx, target)
}

// Fetch delegates to the underlying store.
func (s *sizeLimitedStore) Fetch(ctx context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	return s.store.Fetch(ctx, target)
}

// Resolve delegates to the underlying store.
func (s *sizeLimitedStore) Resolve(ctx context.Context, reference string) (ocispec.Descriptor, error) {
	return s.store.Resolve(ctx, reference)
}

// Tag delegates to the underlying store.
func (s *sizeLimitedStore) Tag(ctx context.Context, desc ocispec.Descriptor, reference string) error {
	return s.store.Tag(ctx, desc, reference)
}

// Predecessors delegates to the underlying store.
func (s *sizeLimitedStore) Predecessors(
	ctx context.Context, node ocispec.Descriptor,
) ([]ocispec.Descriptor, error) {
	return s.store.Predecessors(ctx, node)
}

// Push validates content size before storing to prevent OOM attacks.
func (s *sizeLimitedStore) Push(ctx context.Context, desc ocispec.Descriptor, content io.Reader) error {
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

	// Wrap the reader to enforce the limit in case descriptor.Size is lying
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

	if err := s.store.Push(ctx, desc, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("pushing to underlying store: %w", err)
	}
	return nil
}

// isManifestMediaType returns true if the media type is a manifest or index type.
func isManifestMediaType(mediaType string) bool {
	switch mediaType {
	case MediaTypeImageManifest, MediaTypeImageIndex,
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
func (r *Registry) defaultNewTarget(ref registry.Reference) (registryTarget, error) {
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

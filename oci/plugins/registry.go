// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"fmt"

	"github.com/opencontainers/go-digest"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"

	"github.com/stacklok/toolhive-core/oci/artifact"
)

// Compile-time interface check.
var _ RegistryClient = (*Registry)(nil)

// Registry provides operations for pushing and pulling plugins from OCI registries.
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

// Push pushes a plugin artifact from the local store to a remote registry.
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

	// Copy the content graph (blobs → manifests → index) to the remote.
	if err := oras.CopyGraph(ctx, store.Target(), target, desc, oras.DefaultCopyGraphOptions); err != nil {
		return fmt.Errorf("pushing to registry: %w", err)
	}

	// Tag on the remote with the requested reference.
	if err := target.Tag(ctx, desc, parsedRef.Reference); err != nil {
		return fmt.Errorf("tagging remote: %w", err)
	}

	return nil
}

// Pull pulls a plugin artifact from a remote registry to the local store.
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

	validated := artifact.NewValidatingTarget(store.Target())

	// Copy from remote to the validated local store, tagging locally under the
	// full OCI reference. The local store is shared across all plugins, so using
	// the bare tag (e.g. "v1.0.0") as the destination would let one plugin's
	// pull silently overwrite another plugin's identically-tagged entry.
	desc, err := oras.Copy(
		ctx, target, parsedRef.Reference, validated, ref, oras.DefaultCopyOptions,
	)
	if err != nil {
		return "", fmt.Errorf("pulling from registry: %w", err)
	}

	return desc.Digest, nil
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
		Client:     retry.DefaultClient,
		Credential: credentials.Credential(r.credStore),
	}
	repo.PlainHTTP = r.plainHTTP

	return repo, nil
}

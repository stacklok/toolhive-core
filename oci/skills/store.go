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
	"net/http"
	"os"
	"path/filepath"

	"github.com/adrg/xdg"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"

	"github.com/stacklok/toolhive-core/httperr"
)

// Store provides local OCI artifact storage backed by an OCI Image Layout.
type Store struct {
	root  string
	inner *oci.Store
}

// NewStore creates a new local OCI store at the given root directory.
// The directory is initialized as an OCI Image Layout with blobs/, oci-layout, and index.json.
func NewStore(root string) (*Store, error) {
	inner, err := oci.New(root)
	if err != nil {
		return nil, fmt.Errorf("creating OCI store at %s: %w", root, err)
	}

	return &Store{root: root, inner: inner}, nil
}

// StoreRoot returns the skills store root within the given data home directory.
// This is the injectable, testable form. For the standard XDG location, use DefaultStoreRoot.
func StoreRoot(dataHome string) string {
	return filepath.Join(dataHome, "toolhive", "skills")
}

// DefaultStoreRoot returns the default store root directory using XDG base directory conventions.
func DefaultStoreRoot() string {
	return StoreRoot(xdg.DataHome)
}

// PutBlob stores a blob and returns its digest.
func (s *Store) PutBlob(ctx context.Context, content []byte) (digest.Digest, error) {
	d := digest.FromBytes(content)
	desc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    d,
		Size:      int64(len(content)),
	}

	if err := s.inner.Push(ctx, desc, bytes.NewReader(content)); err != nil {
		if errors.Is(err, errdef.ErrAlreadyExists) {
			return d, nil
		}
		return "", fmt.Errorf("writing blob: %w", err)
	}

	return d, nil
}

// GetBlob retrieves a blob by digest.
func (s *Store) GetBlob(ctx context.Context, d digest.Digest) ([]byte, error) {
	data, err := s.fetchContent(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("blob not found: %s: %w", d, err)
	}
	return data, nil
}

// PutManifest stores a manifest and returns its digest.
func (s *Store) PutManifest(ctx context.Context, content []byte) (digest.Digest, error) {
	d := digest.FromBytes(content)

	// Parse media type from content so oci.Store indexes it correctly.
	var header struct {
		MediaType string `json:"mediaType"`
	}
	mediaType := "application/octet-stream"
	if err := json.Unmarshal(content, &header); err == nil && header.MediaType != "" {
		mediaType = header.MediaType
	}

	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    d,
		Size:      int64(len(content)),
	}

	if err := s.inner.Push(ctx, desc, bytes.NewReader(content)); err != nil {
		if errors.Is(err, errdef.ErrAlreadyExists) {
			return d, nil
		}
		return "", fmt.Errorf("writing manifest: %w", err)
	}

	return d, nil
}

// GetManifest retrieves a manifest by digest.
func (s *Store) GetManifest(ctx context.Context, d digest.Digest) ([]byte, error) {
	data, err := s.fetchContent(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("manifest not found: %s: %w", d, err)
	}
	return data, nil
}

// Tag associates a tag with a manifest digest.
func (s *Store) Tag(ctx context.Context, d digest.Digest, tag string) error {
	// Resolve the digest to get the full descriptor (manifests are auto-tagged by digest on Push).
	desc, err := s.inner.Resolve(ctx, d.String())
	if err != nil {
		return fmt.Errorf("resolving digest for tag: %w", err)
	}

	if err := s.inner.Tag(ctx, desc, tag); err != nil {
		return fmt.Errorf("tagging: %w", err)
	}

	return nil
}

// DeleteTag removes a tag from the store index without deleting the underlying blobs.
func (s *Store) DeleteTag(ctx context.Context, tag string) error {
	if err := s.inner.Untag(ctx, tag); err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return httperr.WithCode(
				fmt.Errorf("tag not found: %s: %w", tag, err),
				http.StatusNotFound,
			)
		}
		return fmt.Errorf("removing tag: %w", err)
	}
	return nil
}

// DeleteBuild removes a tag and, if no other tag shares the same digest,
// deletes all associated blobs (config, layers, manifest, and index if applicable).
// Use DeleteTag when tag-only removal is desired and blob cleanup is not needed.
func (s *Store) DeleteBuild(ctx context.Context, tag string) error {
	d, err := s.Resolve(ctx, tag)
	if err != nil {
		return httperr.WithCode(
			fmt.Errorf("tag not found: %s: %w", tag, err),
			http.StatusNotFound,
		)
	}

	if err := s.DeleteTag(ctx, tag); err != nil {
		return err
	}

	shared, err := s.isDigestReferenced(ctx, d)
	if err != nil {
		return fmt.Errorf("checking remaining references: %w", err)
	}
	if shared {
		return nil
	}

	return s.deleteOrphanedBlobs(ctx, d)
}

// Resolve resolves a tag to a manifest digest.
func (s *Store) Resolve(ctx context.Context, tag string) (digest.Digest, error) {
	desc, err := s.inner.Resolve(ctx, tag)
	if err != nil {
		return "", fmt.Errorf("tag not found: %s: %w", tag, err)
	}
	return desc.Digest, nil
}

// ListTags returns all tags in the store.
func (s *Store) ListTags(ctx context.Context) ([]string, error) {
	var tags []string
	if err := s.inner.Tags(ctx, "", func(t []string) error {
		tags = append(tags, t...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("listing tags: %w", err)
	}
	return tags, nil
}

// GetIndex retrieves and parses an image index by digest.
func (s *Store) GetIndex(ctx context.Context, d digest.Digest) (*ocispec.Index, error) {
	data, err := s.fetchContent(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("getting index: %w", err)
	}

	var index ocispec.Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}

	return &index, nil
}

// IsIndex checks if the content at the given digest is an image index.
func (s *Store) IsIndex(ctx context.Context, d digest.Digest) (bool, error) {
	data, err := s.fetchContent(ctx, d)
	if err != nil {
		return false, fmt.Errorf("manifest not found: %s: %w", d, err)
	}

	var header struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return false, fmt.Errorf("parsing media type: %w", err)
	}

	return header.MediaType == ocispec.MediaTypeImageIndex, nil
}

// Root returns the store root directory.
func (s *Store) Root() string {
	return s.root
}

// Target returns the underlying oras.Target for direct use by registry operations.
func (s *Store) Target() oras.Target {
	return s.inner
}

// fetchContent retrieves raw content by digest from the underlying store.
func (s *Store) fetchContent(ctx context.Context, d digest.Digest) ([]byte, error) {
	// oci.Store's Fetch only uses the Digest field to locate blobs in blobs/<algo>/<hex>.
	rc, err := s.inner.Fetch(ctx, ocispec.Descriptor{Digest: d})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	return data, nil
}

// isDigestReferenced checks whether any remaining tag still resolves to d.
func (s *Store) isDigestReferenced(ctx context.Context, d digest.Digest) (bool, error) {
	tags, err := s.ListTags(ctx)
	if err != nil {
		return false, err
	}
	for _, tag := range tags {
		resolved, err := s.Resolve(ctx, tag)
		if err != nil {
			continue
		}
		if resolved == d {
			return true, nil
		}
	}
	return false, nil
}

// deleteOrphanedBlobs removes all blobs reachable from d (index or manifest),
// including d itself. Callers must ensure no remaining tag references d.
func (s *Store) deleteOrphanedBlobs(ctx context.Context, d digest.Digest) error {
	isIdx, err := s.IsIndex(ctx, d)
	if err != nil {
		return fmt.Errorf("inspecting orphaned digest: %w", err)
	}

	if isIdx {
		idx, err := s.GetIndex(ctx, d)
		if err != nil {
			return fmt.Errorf("fetching orphaned index: %w", err)
		}
		for _, m := range idx.Manifests {
			if err := s.deleteManifestBlobs(ctx, m.Digest); err != nil {
				return err
			}
		}
	} else {
		if err := s.deleteManifestBlobs(ctx, d); err != nil {
			return err
		}
		// deleteManifestBlobs already deletes d when it's a plain manifest.
		return nil
	}

	return s.deleteBlob(d)
}

// deleteManifestBlobs fetches the manifest at d, deletes its config and layer
// blobs, then deletes the manifest blob itself.
func (s *Store) deleteManifestBlobs(ctx context.Context, d digest.Digest) error {
	data, err := s.fetchContent(ctx, d)
	if err != nil {
		return fmt.Errorf("fetching manifest %s: %w", d, err)
	}

	var m ocispec.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parsing manifest %s: %w", d, err)
	}

	if err := s.deleteBlob(m.Config.Digest); err != nil {
		return err
	}
	for _, layer := range m.Layers {
		if err := s.deleteBlob(layer.Digest); err != nil {
			return err
		}
	}
	return s.deleteBlob(d)
}

// deleteBlob removes the blob file for d from the local OCI layout.
// A missing file is treated as success (idempotent).
func (s *Store) deleteBlob(d digest.Digest) error {
	path := filepath.Join(s.root, "blobs", d.Algorithm().String(), d.Encoded())
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting blob %s: %w", d, err)
	}
	return nil
}

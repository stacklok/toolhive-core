// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/adrg/xdg"
	"github.com/opencontainers/go-digest"
)

// Store provides local OCI artifact storage.
type Store struct {
	root string
	mu   sync.RWMutex
}

// Index tracks tags to digests mapping.
type Index struct {
	Tags map[string]string `json:"tags"` // tag -> digest string
}

// NewStore creates a new local OCI store at the given root directory.
func NewStore(root string) (*Store, error) {
	// Create directory structure
	dirs := []string{
		filepath.Join(root, "blobs", "sha256"),
		filepath.Join(root, "manifests"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("creating store directory %s: %w", dir, err)
		}
	}

	return &Store{root: root}, nil
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
func (s *Store) PutBlob(_ context.Context, content []byte) (digest.Digest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d := digest.FromBytes(content)
	blobPath := s.blobPath(d)

	// Check if blob already exists
	if _, err := os.Stat(blobPath); err == nil {
		return d, nil
	}

	if err := os.WriteFile(blobPath, content, 0600); err != nil {
		return "", fmt.Errorf("writing blob: %w", err)
	}

	return d, nil
}

// GetBlob retrieves a blob by digest.
func (s *Store) GetBlob(_ context.Context, d digest.Digest) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	blobPath := s.blobPath(d)
	content, err := os.ReadFile(blobPath) //#nosec G304 -- path is constructed from validated digest
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blob not found: %s", d)
		}
		return nil, fmt.Errorf("reading blob: %w", err)
	}

	return content, nil
}

// PutManifest stores a manifest and returns its digest.
func (s *Store) PutManifest(_ context.Context, content []byte) (digest.Digest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d := digest.FromBytes(content)
	manifestPath := s.manifestPath(d)

	if err := os.WriteFile(manifestPath, content, 0600); err != nil {
		return "", fmt.Errorf("writing manifest: %w", err)
	}

	return d, nil
}

// GetManifest retrieves a manifest by digest.
func (s *Store) GetManifest(_ context.Context, d digest.Digest) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getManifest(d)
}

// getManifest reads a manifest without locking. Caller must hold mu.
func (s *Store) getManifest(d digest.Digest) ([]byte, error) {
	manifestPath := s.manifestPath(d)
	content, err := os.ReadFile(manifestPath) //#nosec G304 -- path is constructed from validated digest
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("manifest not found: %s", d)
		}
		return nil, fmt.Errorf("reading manifest: %w", err)
	}

	return content, nil
}

// Tag associates a tag with a manifest digest.
func (s *Store) Tag(_ context.Context, d digest.Digest, tag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.loadIndex()
	if err != nil {
		return err
	}

	index.Tags[tag] = d.String()

	return s.saveIndex(index)
}

// Resolve resolves a tag to a manifest digest.
func (s *Store) Resolve(_ context.Context, tag string) (digest.Digest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	index, err := s.loadIndex()
	if err != nil {
		return "", err
	}

	digestStr, ok := index.Tags[tag]
	if !ok {
		return "", fmt.Errorf("tag not found: %s", tag)
	}

	return digest.Parse(digestStr)
}

// ListTags returns all tags in the store.
func (s *Store) ListTags(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	index, err := s.loadIndex()
	if err != nil {
		return nil, err
	}

	tags := make([]string, 0, len(index.Tags))
	for tag := range index.Tags {
		tags = append(tags, tag)
	}

	return tags, nil
}

// GetIndex retrieves and parses an image index by digest.
func (s *Store) GetIndex(_ context.Context, d digest.Digest) (*ImageIndex, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.getManifest(d)
	if err != nil {
		return nil, fmt.Errorf("getting index: %w", err)
	}

	var index ImageIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}

	return &index, nil
}

// IsIndex checks if the content at the given digest is an image index.
func (s *Store) IsIndex(_ context.Context, d digest.Digest) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.getManifest(d)
	if err != nil {
		return false, err
	}

	// Check media type field
	var header struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return false, fmt.Errorf("parsing media type: %w", err)
	}

	return header.MediaType == MediaTypeImageIndex, nil
}

// Root returns the store root directory.
func (s *Store) Root() string {
	return s.root
}

// blobPath returns the path for a blob with the given digest.
func (s *Store) blobPath(d digest.Digest) string {
	return filepath.Join(s.root, "blobs", d.Algorithm().String(), d.Encoded())
}

// manifestPath returns the path for a manifest with the given digest.
func (s *Store) manifestPath(d digest.Digest) string {
	return filepath.Join(s.root, "manifests", d.Encoded())
}

// indexPath returns the path to the index file.
func (s *Store) indexPath() string {
	return filepath.Join(s.root, "index.json")
}

// loadIndex loads the tag index from disk.
func (s *Store) loadIndex() (*Index, error) {
	indexPath := s.indexPath()

	data, err := os.ReadFile(indexPath) //#nosec G304 -- path is constructed from store root
	if err != nil {
		if os.IsNotExist(err) {
			return &Index{Tags: make(map[string]string)}, nil
		}
		return nil, fmt.Errorf("reading index: %w", err)
	}

	var index Index
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}

	if index.Tags == nil {
		index.Tags = make(map[string]string)
	}

	return &index, nil
}

// saveIndex saves the tag index to disk.
func (s *Store) saveIndex(index *Index) error {
	indexPath := s.indexPath()

	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling index: %w", err)
	}

	if err := os.WriteFile(indexPath, data, 0600); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}

	return nil
}

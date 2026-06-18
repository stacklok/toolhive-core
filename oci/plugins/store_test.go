// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/httperr"
	"github.com/stacklok/toolhive-core/oci/artifact"
)

func TestNewStore(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	storePath := filepath.Join(tmpDir, "store")

	store, err := NewStore(storePath)
	require.NoError(t, err)
	assert.Equal(t, storePath, store.Root())

	blobsDir := filepath.Join(storePath, "blobs")
	_, err = os.Stat(blobsDir)
	assert.NoError(t, err, "blobs directory should exist")

	ociLayoutFile := filepath.Join(storePath, "oci-layout")
	_, err = os.Stat(ociLayoutFile)
	assert.NoError(t, err, "oci-layout file should exist")

	indexFile := filepath.Join(storePath, "index.json")
	_, err = os.Stat(indexFile)
	assert.NoError(t, err, "index.json file should exist")
}

func TestStore_PutGetBlob(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	content := []byte("test blob content")

	d, err := store.PutBlob(ctx, content)
	require.NoError(t, err)
	assert.Equal(t, digest.FromBytes(content), d)

	retrieved, err := store.GetBlob(ctx, d)
	require.NoError(t, err)
	assert.Equal(t, content, retrieved)
}

func TestStore_PutBlob_Idempotent(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	content := []byte("test blob content")

	d1, err := store.PutBlob(ctx, content)
	require.NoError(t, err)

	d2, err := store.PutBlob(ctx, content)
	require.NoError(t, err)

	assert.Equal(t, d1, d2, "putting the same content twice should return the same digest")
}

func TestStore_GetBlob_NotFound(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	fakeDigest := digest.FromString("nonexistent")

	_, err = store.GetBlob(ctx, fakeDigest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blob not found")
}

func TestStore_PutGetManifest(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}`)

	d, err := store.PutManifest(ctx, manifest)
	require.NoError(t, err)

	retrieved, err := store.GetManifest(ctx, d)
	require.NoError(t, err)
	assert.Equal(t, manifest, retrieved)
}

func TestStore_TagResolve(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}`)

	d, err := store.PutManifest(ctx, manifest)
	require.NoError(t, err)

	tag := "ghcr.io/myorg/my-plugin:v1.0.0"
	err = store.Tag(ctx, d, tag)
	require.NoError(t, err)

	resolved, err := store.Resolve(ctx, tag)
	require.NoError(t, err)
	assert.Equal(t, d, resolved)
}

func TestStore_Resolve_NotFound(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	_, err = store.Resolve(ctx, "nonexistent:tag")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tag not found")
}

func TestStore_ListTags(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	tags, err := store.ListTags(ctx)
	require.NoError(t, err)
	assert.Empty(t, tags)

	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}`)
	d, err := store.PutManifest(ctx, manifest)
	require.NoError(t, err)

	expectedTags := []string{"tag1", "tag2", "tag3"}
	for _, tag := range expectedTags {
		err = store.Tag(ctx, d, tag)
		require.NoError(t, err)
	}

	tags, err = store.ListTags(ctx)
	require.NoError(t, err)
	assert.Len(t, tags, len(expectedTags))
	for _, expected := range expectedTags {
		assert.Contains(t, tags, expected)
	}
}

func TestStore_TagOverwrite(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	manifest1 := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "version": 1}`)
	manifest2 := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "version": 2}`)

	d1, err := store.PutManifest(ctx, manifest1)
	require.NoError(t, err)

	d2, err := store.PutManifest(ctx, manifest2)
	require.NoError(t, err)

	tag := "my-plugin:latest"
	err = store.Tag(ctx, d1, tag)
	require.NoError(t, err)

	err = store.Tag(ctx, d2, tag)
	require.NoError(t, err)

	resolved, err := store.Resolve(ctx, tag)
	require.NoError(t, err)
	assert.Equal(t, d2, resolved, "tag should resolve to the second manifest after overwrite")
}

func TestStore_GetIndex(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	idx := &ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("test"),
				Size:      100,
				Platform:  &ocispec.Platform{OS: artifact.OSLinux, Architecture: artifact.ArchAMD64},
			},
		},
	}
	idx.SchemaVersion = 2

	data, err := json.Marshal(idx)
	require.NoError(t, err)

	d, err := store.PutManifest(ctx, data)
	require.NoError(t, err)

	got, err := store.GetIndex(ctx, d)
	require.NoError(t, err)
	assert.Equal(t, 2, got.SchemaVersion)
	assert.Equal(t, ocispec.MediaTypeImageIndex, got.MediaType)
	require.Len(t, got.Manifests, 1)
	assert.Equal(t, artifact.OSLinux, got.Manifests[0].Platform.OS)
	assert.Equal(t, artifact.ArchAMD64, got.Manifests[0].Platform.Architecture)
}

func TestStore_IsIndex(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	idx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
	}
	idx.SchemaVersion = 2
	indexData, err := json.Marshal(idx)
	require.NoError(t, err)

	indexDigest, err := store.PutManifest(ctx, indexData)
	require.NoError(t, err)

	isIdx, err := store.IsIndex(ctx, indexDigest)
	require.NoError(t, err)
	assert.True(t, isIdx)

	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}`)
	manifestDigest, err := store.PutManifest(ctx, manifest)
	require.NoError(t, err)

	isIdx, err = store.IsIndex(ctx, manifestDigest)
	require.NoError(t, err)
	assert.False(t, isIdx)
}

func TestStore_DeleteTag(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	manifest := []byte(`{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json"}`)
	d, err := store.PutManifest(ctx, manifest)
	require.NoError(t, err)

	tag := "my-plugin:v1"
	require.NoError(t, store.Tag(ctx, d, tag))
	require.NoError(t, store.DeleteTag(ctx, tag))

	_, err = store.Resolve(ctx, tag)
	require.Error(t, err)
}

func TestStore_DeleteTag_NotFound(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	err = store.DeleteTag(context.Background(), "missing")
	require.Error(t, err)
	assert.Equal(t, http.StatusNotFound, httperr.Code(err))
}

func TestStoreRoot(t *testing.T) {
	t.Parallel()

	assert.Equal(t, filepath.Join("tmp", "data", "toolhive", "plugins"), StoreRoot(filepath.Join("tmp", "data")))
}

func TestDefaultStoreRoot(t *testing.T) {
	t.Parallel()

	root := DefaultStoreRoot()
	assert.True(t, strings.HasSuffix(root, filepath.Join("toolhive", "plugins")))
}

// putTestManifest creates a realistic OCI artifact (config + layer + manifest)
// in the store WITHOUT tagging it, and returns the config, layer, and manifest digests.
func putTestManifest(ctx context.Context, t *testing.T, s *Store) (configDigest, layerDigest, manifestDigest digest.Digest) {
	t.Helper()

	configData := []byte(`{"architecture":"amd64","os":"linux"}`)
	configDigest, err := s.PutBlob(ctx, configData)
	require.NoError(t, err)

	layerData := []byte("fake layer content")
	layerDigest, err = s.PutBlob(ctx, layerData)
	require.NoError(t, err)

	manifestContent, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configData)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      int64(len(layerData)),
			},
		},
	})
	require.NoError(t, err)

	manifestDigest, err = s.PutManifest(ctx, manifestContent)
	require.NoError(t, err)

	return configDigest, layerDigest, manifestDigest
}

// putTestArtifact creates a realistic OCI artifact (config + layer + manifest)
// in the store, tags it with the given tag, and returns the config, layer, and manifest digests.
func putTestArtifact(ctx context.Context, t *testing.T, s *Store, tag string) (configDigest, layerDigest, manifestDigest digest.Digest) {
	t.Helper()
	configDigest, layerDigest, manifestDigest = putTestManifest(ctx, t, s)
	require.NoError(t, s.Tag(ctx, manifestDigest, tag))
	return configDigest, layerDigest, manifestDigest
}

// blobExists reports whether the blob file for d is present on disk.
func blobExists(t *testing.T, s *Store, d digest.Digest) bool {
	t.Helper()
	path := filepath.Join(s.Root(), "blobs", d.Algorithm().String(), d.Encoded())
	_, err := os.Stat(path)
	return err == nil
}

func TestStore_DeleteBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setup     func(t *testing.T, s *Store, ctx context.Context) (configDigest, layerDigest, manifestDigest digest.Digest)
		tag       string
		wantErr   bool
		wantCode  int
		postCheck func(t *testing.T, s *Store, ctx context.Context, configDigest, layerDigest, manifestDigest digest.Digest)
	}{
		{
			name: "removes tag and blobs when no other tag shares the digest",
			setup: func(t *testing.T, s *Store, ctx context.Context) (digest.Digest, digest.Digest, digest.Digest) {
				t.Helper()
				return putTestArtifact(ctx, t, s, "v1")
			},
			tag: "v1",
			postCheck: func(t *testing.T, s *Store, ctx context.Context, configDigest, layerDigest, manifestDigest digest.Digest) {
				t.Helper()
				_, err := s.Resolve(ctx, "v1")
				assert.Error(t, err, "tag should be gone")

				assert.False(t, blobExists(t, s, manifestDigest), "manifest blob should be deleted")
				assert.False(t, blobExists(t, s, configDigest), "config blob should be deleted")
				assert.False(t, blobExists(t, s, layerDigest), "layer blob should be deleted")
			},
		},
		{
			name: "keeps blobs when another tag shares the same digest",
			setup: func(t *testing.T, s *Store, ctx context.Context) (digest.Digest, digest.Digest, digest.Digest) {
				t.Helper()
				c, l, m := putTestArtifact(ctx, t, s, "v1")
				require.NoError(t, s.Tag(ctx, m, "v2"))
				return c, l, m
			},
			tag: "v1",
			postCheck: func(t *testing.T, s *Store, ctx context.Context, configDigest, layerDigest, manifestDigest digest.Digest) {
				t.Helper()
				resolved, err := s.Resolve(ctx, "v2")
				require.NoError(t, err)
				assert.Equal(t, manifestDigest, resolved, "v2 should still resolve")

				assert.True(t, blobExists(t, s, manifestDigest), "manifest blob should be retained")
				assert.True(t, blobExists(t, s, configDigest), "config blob should be retained")
				assert.True(t, blobExists(t, s, layerDigest), "layer blob should be retained")
			},
		},
		{
			name: "returns 404 when tag does not exist",
			setup: func(_ *testing.T, _ *Store, _ context.Context) (digest.Digest, digest.Digest, digest.Digest) {
				return "", "", ""
			},
			tag:      "nonexistent",
			wantErr:  true,
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewStore(t.TempDir())
			require.NoError(t, err)

			ctx := context.Background()
			configDigest, layerDigest, manifestDigest := tt.setup(t, store, ctx)

			err = store.DeleteBuild(ctx, tt.tag)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantCode != 0 {
					assert.Equal(t, tt.wantCode, httperr.Code(err))
				}
				return
			}

			require.NoError(t, err)
			if tt.postCheck != nil {
				tt.postCheck(t, store, ctx, configDigest, layerDigest, manifestDigest)
			}
		})
	}
}

// TestStore_DeleteBuild_Index covers the deleteOrphanedBlobs index branch: a
// tagged image index must, on deletion, recursively delete every referenced
// manifest and its config/layer blobs as well as the index blob itself.
func TestStore_DeleteBuild_Index(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)
	ctx := context.Background()

	configDigest, layerDigest, manifestDigest := putTestManifest(ctx, t, store)

	indexContent, err := json.Marshal(ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
			},
		},
	})
	require.NoError(t, err)

	indexDigest, err := store.PutManifest(ctx, indexContent)
	require.NoError(t, err)
	require.NoError(t, store.Tag(ctx, indexDigest, "v1"))

	require.NoError(t, store.DeleteBuild(ctx, "v1"))

	_, err = store.Resolve(ctx, "v1")
	assert.Error(t, err, "tag should be gone")

	assert.False(t, blobExists(t, store, indexDigest), "index blob should be deleted")
	assert.False(t, blobExists(t, store, manifestDigest), "manifest blob should be deleted")
	assert.False(t, blobExists(t, store, configDigest), "config blob should be deleted")
	assert.False(t, blobExists(t, store, layerDigest), "layer blob should be deleted")
}

// TestStore_deleteBlob_RejectsInvalidDigest guards the path-traversal fix: a
// digest that is not a well-formed algorithm:hex pair must be rejected before
// it can be turned into a filesystem path.
func TestStore_deleteBlob_RejectsInvalidDigest(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	err = store.deleteBlob(digest.Digest("sha256:../../../../etc/passwd"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid digest")
}

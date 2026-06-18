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

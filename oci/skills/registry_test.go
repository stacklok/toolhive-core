// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"
)

func TestNewRegistry_Default(t *testing.T) {
	t.Parallel()

	reg, err := NewRegistry()
	require.NoError(t, err)
	assert.NotNil(t, reg)
	assert.NotNil(t, reg.credStore, "default credential store should be set")
	assert.False(t, reg.plainHTTP, "plainHTTP should default to false")
}

func TestNewRegistry_WithOptions(t *testing.T) {
	t.Parallel()

	reg, err := NewRegistry(
		WithPlainHTTP(true),
	)
	require.NoError(t, err)
	assert.True(t, reg.plainHTTP, "plainHTTP should be set by option")
}

func TestParseReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ref     string
		wantErr bool
	}{
		{"valid tag", "ghcr.io/myorg/skill:v1.0.0", false},
		{"valid digest", "ghcr.io/myorg/skill@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"missing tag or digest", "ghcr.io/myorg/skill", true},
		{"invalid reference", ":::invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseReference(tt.ref)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestIsManifestMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mediaType string
		want      bool
	}{
		{"OCI manifest", MediaTypeImageManifest, true},
		{"OCI index", MediaTypeImageIndex, true},
		{"Docker manifest", "application/vnd.docker.distribution.manifest.v2+json", true},
		{"Docker manifest list", "application/vnd.docker.distribution.manifest.list.v2+json", true},
		{"OCI config", "application/vnd.oci.image.config.v1+json", false},
		{"OCI layer", "application/vnd.oci.image.layer.v1.tar+gzip", false},
		{"octet-stream", "application/octet-stream", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isManifestMediaType(tt.mediaType))
		})
	}
}

// --- validatingTarget tests ---

func TestValidatingTarget_RejectOversizedContent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	vt := newValidatingTarget(memory.New())

	oversized := make([]byte, MaxManifestSize+1)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    digest.FromBytes(oversized),
		Size:      int64(len(oversized)),
	}

	err := vt.Push(ctx, desc, bytes.NewReader(oversized))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestValidatingTarget_RejectLyingDescriptor(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	vt := newValidatingTarget(memory.New())

	oversized := make([]byte, MaxManifestSize+1)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    digest.FromBytes(oversized),
		Size:      10, // lying
	}

	err := vt.Push(ctx, desc, bytes.NewReader(oversized))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestValidatingTarget_RejectNegativeSize(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	vt := newValidatingTarget(memory.New())

	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    digest.FromString("test"),
		Size:      -1,
	}

	err := vt.Push(ctx, desc, bytes.NewReader([]byte("test")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid negative content size")
}

func TestValidatingTarget_AcceptValidContent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	inner := memory.New()
	vt := newValidatingTarget(inner)

	content := []byte(`{"schemaVersion": 2}`)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    digest.FromBytes(content),
		Size:      int64(len(content)),
	}

	err := vt.Push(ctx, desc, bytes.NewReader(content))
	require.NoError(t, err)

	exists, err := inner.Exists(ctx, desc)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestValidateManifestCounts(t *testing.T) {
	t.Parallel()

	t.Run("too many manifests in index", func(t *testing.T) {
		t.Parallel()
		index := ImageIndex{
			SchemaVersion: 2,
			MediaType:     MediaTypeImageIndex,
			Manifests:     make([]IndexDescriptor, maxIndexManifests+1),
		}
		data, err := json.Marshal(index)
		require.NoError(t, err)

		err = validateManifestCounts(MediaTypeImageIndex, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("too many layers in manifest", func(t *testing.T) {
		t.Parallel()
		manifest := ocispec.Manifest{
			MediaType: MediaTypeImageManifest,
			Layers:    make([]ocispec.Descriptor, maxManifestLayers+1),
		}
		data, err := json.Marshal(manifest)
		require.NoError(t, err)

		err = validateManifestCounts(MediaTypeImageManifest, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("valid counts", func(t *testing.T) {
		t.Parallel()
		manifest := ocispec.Manifest{
			MediaType: MediaTypeImageManifest,
			Layers:    make([]ocispec.Descriptor, 2),
		}
		data, err := json.Marshal(manifest)
		require.NoError(t, err)

		err = validateManifestCounts(MediaTypeImageManifest, data)
		require.NoError(t, err)
	})
}

// --- storeAdapter tests ---

func TestStoreAdapter_PushFetchRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)
	adapter := newStoreAdapter(store)

	// Push a blob
	blobContent := []byte("test blob data")
	blobDesc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    digest.FromBytes(blobContent),
		Size:      int64(len(blobContent)),
	}
	err = adapter.Push(ctx, blobDesc, bytes.NewReader(blobContent))
	require.NoError(t, err)

	// Fetch it back
	rc, err := adapter.Fetch(ctx, blobDesc)
	require.NoError(t, err)
	defer rc.Close()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(rc)
	require.NoError(t, err)
	assert.Equal(t, blobContent, buf.Bytes())

	// Exists
	exists, err := adapter.Exists(ctx, blobDesc)
	require.NoError(t, err)
	assert.True(t, exists)

	// Non-existent
	fakeDesc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    digest.FromString("fake"),
		Size:      4,
	}
	exists, err = adapter.Exists(ctx, fakeDesc)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestStoreAdapter_ResolveAndTag(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)
	adapter := newStoreAdapter(store)

	// Build and store a manifest
	manifest := ocispec.Manifest{MediaType: MediaTypeImageManifest}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	manifestDigest, err := store.PutManifest(ctx, manifestBytes)
	require.NoError(t, err)

	// Tag via adapter
	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(manifestBytes)),
	}
	err = adapter.Tag(ctx, desc, "my-tag")
	require.NoError(t, err)

	// Resolve via adapter
	resolved, err := adapter.Resolve(ctx, "my-tag")
	require.NoError(t, err)
	assert.Equal(t, manifestDigest, resolved.Digest)
	assert.Equal(t, MediaTypeImageManifest, resolved.MediaType)
}

// --- Integration tests using in-memory target ---

func newTestRegistry(t *testing.T, remoteStore *memory.Store) *Registry {
	t.Helper()
	return &Registry{
		newTarget: func(_ registry.Reference) (oras.Target, error) {
			return remoteStore, nil
		},
	}
}

func buildTestManifest(t *testing.T, store *Store) (digest.Digest, []byte) {
	t.Helper()
	ctx := t.Context()

	configContent := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	layerContent := []byte("skill layer content")

	configDigest, err := store.PutBlob(ctx, configContent)
	require.NoError(t, err)
	layerDigest, err := store.PutBlob(ctx, layerContent)
	require.NoError(t, err)

	manifest := ocispec.Manifest{
		MediaType:    MediaTypeImageManifest,
		ArtifactType: ArtifactTypeSkill,
		Config: ocispec.Descriptor{
			MediaType: MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configContent)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: MediaTypeImageLayer,
				Digest:    layerDigest,
				Size:      int64(len(layerContent)),
			},
		},
	}

	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	manifestDigest, err := store.PutManifest(ctx, manifestBytes)
	require.NoError(t, err)

	return manifestDigest, manifestBytes
}

func TestPushPull_ManifestRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	remoteStore := memory.New()

	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	manifestDigest, _ := buildTestManifest(t, localStore)

	reg := newTestRegistry(t, remoteStore)
	ref := "example.com/myorg/my-skill:v1.0.0"

	err = reg.Push(ctx, localStore, manifestDigest, ref)
	require.NoError(t, err)

	// Pull into a fresh store
	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	pulledDigest, err := reg.Pull(ctx, pullStore, ref)
	require.NoError(t, err)
	assert.Equal(t, manifestDigest, pulledDigest)

	// Verify manifest was stored
	got, err := pullStore.GetManifest(ctx, pulledDigest)
	require.NoError(t, err)
	assert.NotEmpty(t, got)

	// Verify tag resolution
	resolved, err := pullStore.Resolve(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, pulledDigest, resolved)
}

func TestPushPull_IndexRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	remoteStore := memory.New()

	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	manifestDigest, manifestBytes := buildTestManifest(t, localStore)

	index := ImageIndex{
		SchemaVersion: 2,
		MediaType:     MediaTypeImageIndex,
		ArtifactType:  ArtifactTypeSkill,
		Manifests: []IndexDescriptor{
			{
				MediaType: MediaTypeImageManifest,
				Digest:    manifestDigest.String(),
				Size:      int64(len(manifestBytes)),
				Platform:  &Platform{OS: "linux", Architecture: "amd64"},
			},
		},
	}

	indexBytes, err := json.Marshal(index)
	require.NoError(t, err)
	indexDigest, err := localStore.PutManifest(ctx, indexBytes)
	require.NoError(t, err)

	reg := newTestRegistry(t, remoteStore)
	ref := "example.com/myorg/my-skill:v2.0.0"

	err = reg.Push(ctx, localStore, indexDigest, ref)
	require.NoError(t, err)

	// Pull into a fresh store
	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	pulledDigest, err := reg.Pull(ctx, pullStore, ref)
	require.NoError(t, err)

	// Verify it's an index
	isIdx, err := pullStore.IsIndex(ctx, pulledDigest)
	require.NoError(t, err)
	assert.True(t, isIdx)

	// Verify index contents
	pulledIndex, err := pullStore.GetIndex(ctx, pulledDigest)
	require.NoError(t, err)
	require.Len(t, pulledIndex.Manifests, 1)
	assert.Equal(t, manifestDigest.String(), pulledIndex.Manifests[0].Digest)

	// Verify manifest is also present
	pulledManifest, err := pullStore.GetManifest(ctx, manifestDigest)
	require.NoError(t, err)
	assert.NotEmpty(t, pulledManifest)

	// Verify tag
	resolved, err := pullStore.Resolve(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, pulledDigest, resolved)
}

func TestPush_InvalidReference(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	reg := newTestRegistry(t, memory.New())
	err = reg.Push(ctx, localStore, digest.FromString("test"), ":::invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing reference")
}

func TestPull_InvalidReference(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	reg := newTestRegistry(t, memory.New())
	_, err = reg.Pull(ctx, localStore, ":::invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing reference")
}

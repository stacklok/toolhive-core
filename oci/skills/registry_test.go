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
		{
			name:    "valid reference with tag",
			ref:     "ghcr.io/myorg/skill:v1.0.0",
			wantErr: false,
		},
		{
			name:    "valid reference with digest",
			ref:     "ghcr.io/myorg/skill@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantErr: false,
		},
		{
			name:    "missing tag or digest",
			ref:     "ghcr.io/myorg/skill",
			wantErr: true,
		},
		{
			name:    "invalid reference",
			ref:     ":::invalid",
			wantErr: true,
		},
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

			got := isManifestMediaType(tt.mediaType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSizeLimitedStore_RejectOversizedContent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newSizeLimitedStore()

	// Create a descriptor that claims to exceed MaxManifestSize
	oversizedManifest := make([]byte, MaxManifestSize+1)
	manifestDigest := digest.FromBytes(oversizedManifest)

	manifestDesc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(oversizedManifest)),
	}

	err := store.Push(ctx, manifestDesc, bytes.NewReader(oversizedManifest))
	require.Error(t, err, "should reject oversized manifest")
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestSizeLimitedStore_RejectLyingDescriptor(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newSizeLimitedStore()

	// Descriptor claims small size but actual content exceeds the limit.
	oversized := make([]byte, MaxManifestSize+1)
	oversizedDigest := digest.FromBytes(oversized)

	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    oversizedDigest,
		Size:      10, // lying about size
	}

	err := store.Push(ctx, desc, bytes.NewReader(oversized))
	require.Error(t, err, "should reject content that exceeds limit regardless of descriptor size")
	assert.Contains(t, err.Error(), "exceeds maximum allowed size")
}

func TestSizeLimitedStore_RejectNegativeSize(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newSizeLimitedStore()

	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    digest.FromString("test"),
		Size:      -1,
	}

	err := store.Push(ctx, desc, bytes.NewReader([]byte("test")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid negative content size")
}

func TestSizeLimitedStore_AcceptValidContent(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	store := newSizeLimitedStore()

	content := []byte(`{"schemaVersion": 2}`)
	contentDigest := digest.FromBytes(content)

	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    contentDigest,
		Size:      int64(len(content)),
	}

	err := store.Push(ctx, desc, bytes.NewReader(content))
	require.NoError(t, err)

	exists, err := store.Exists(ctx, desc)
	require.NoError(t, err)
	assert.True(t, exists, "content should be stored after successful Push")
}

func TestStageBlobs_SharedBlobs(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
	layerContent := []byte("skill content")

	configDigest, err := store.PutBlob(ctx, configContent)
	require.NoError(t, err)

	layerDigest, err := store.PutBlob(ctx, layerContent)
	require.NoError(t, err)

	manifest := &ocispec.Manifest{
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

	memStore := memory.New()
	reg := &Registry{}

	// Stage blobs first time
	err = reg.stageBlobs(ctx, store, memStore, manifest)
	require.NoError(t, err)

	// Stage blobs second time (simulates shared blobs in multi-platform push).
	// Should NOT fail with ErrAlreadyExists.
	err = reg.stageBlobs(ctx, store, memStore, manifest)
	require.NoError(t, err, "should handle already-staged blobs gracefully")
}

func TestStageBlobs_MultipleLayers(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	configContent := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer1Content := []byte("layer 1 content")
	layer2Content := []byte("layer 2 content")

	configDigest, err := store.PutBlob(ctx, configContent)
	require.NoError(t, err)

	layer1Digest, err := store.PutBlob(ctx, layer1Content)
	require.NoError(t, err)

	layer2Digest, err := store.PutBlob(ctx, layer2Content)
	require.NoError(t, err)

	manifest := &ocispec.Manifest{
		Config: ocispec.Descriptor{
			MediaType: MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configContent)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: MediaTypeImageLayer,
				Digest:    layer1Digest,
				Size:      int64(len(layer1Content)),
			},
			{
				MediaType: MediaTypeImageLayer,
				Digest:    layer2Digest,
				Size:      int64(len(layer2Content)),
			},
		},
	}

	memStore := memory.New()
	reg := &Registry{}

	err = reg.stageBlobs(ctx, store, memStore, manifest)
	require.NoError(t, err)

	// Verify blobs were staged
	exists, err := memStore.Exists(ctx, manifest.Config)
	require.NoError(t, err)
	assert.True(t, exists, "config blob should be staged")

	for i, layer := range manifest.Layers {
		exists, err := memStore.Exists(ctx, layer)
		require.NoError(t, err)
		assert.True(t, exists, "layer %d blob should be staged", i)
	}
}

func TestFetchManifest_ValidManifest(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	memStore := memory.New()

	manifest := ocispec.Manifest{
		MediaType: MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: MediaTypeImageConfig,
			Digest:    digest.FromString("config"),
			Size:      10,
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	manifestDigest := digest.FromBytes(manifestBytes)
	desc := ocispec.Descriptor{
		MediaType: MediaTypeImageManifest,
		Digest:    manifestDigest,
		Size:      int64(len(manifestBytes)),
	}
	err = memStore.Push(ctx, desc, bytes.NewReader(manifestBytes))
	require.NoError(t, err)

	reg := &Registry{}
	got, gotBytes, err := reg.fetchManifest(ctx, memStore, desc)
	require.NoError(t, err)
	assert.Equal(t, manifestBytes, gotBytes)
	assert.Equal(t, MediaTypeImageManifest, got.MediaType)
}

func TestFetchManifest_OversizedManifest(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	memStore := memory.New()

	// Build valid JSON that exceeds MaxManifestSize.
	// We use a generic media type to avoid memory.Store trying to parse it
	// as an OCI manifest (which would fail for large synthetic payloads).
	padding := make([]byte, MaxManifestSize)
	for i := range padding {
		padding[i] = 'x'
	}
	oversized := []byte(`{"padding":"` + string(padding) + `"}`)
	oversizedDigest := digest.FromBytes(oversized)
	desc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    oversizedDigest,
		Size:      int64(len(oversized)),
	}
	err := memStore.Push(ctx, desc, bytes.NewReader(oversized))
	require.NoError(t, err)

	reg := &Registry{}
	_, _, err = reg.fetchManifest(ctx, memStore, desc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestStoreBlobFromMemory_ValidBlob(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	memStore := memory.New()

	blobContent := []byte("test blob data")
	blobDigest := digest.FromBytes(blobContent)
	desc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    blobDigest,
		Size:      int64(len(blobContent)),
	}
	err = memStore.Push(ctx, desc, bytes.NewReader(blobContent))
	require.NoError(t, err)

	err = storeBlobFromMemory(ctx, localStore, memStore, desc)
	require.NoError(t, err)

	// Verify it was stored locally
	got, err := localStore.GetBlob(ctx, blobDigest)
	require.NoError(t, err)
	assert.Equal(t, blobContent, got)
}

func TestStoreBlobFromMemory_OversizedBlob(t *testing.T) {
	t.Parallel()

	ctx := t.Context()

	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	memStore := memory.New()

	oversized := make([]byte, MaxBlobSize+1)
	oversizedDigest := digest.FromBytes(oversized)
	desc := ocispec.Descriptor{
		MediaType: "application/octet-stream",
		Digest:    oversizedDigest,
		Size:      int64(len(oversized)),
	}
	err = memStore.Push(ctx, desc, bytes.NewReader(oversized))
	require.NoError(t, err)

	err = storeBlobFromMemory(ctx, localStore, memStore, desc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

// newTestRegistry creates a Registry with an in-memory target for integration testing.
// The returned memory.Store is used as both push destination and pull source.
func newTestRegistry(t *testing.T, remoteStore *memory.Store) *Registry {
	t.Helper()
	return &Registry{
		newTarget: func(_ registry.Reference) (registryTarget, error) {
			return remoteStore, nil
		},
	}
}

// buildTestManifest creates a valid OCI manifest with config and layer in the local store.
// Returns the manifest digest and the raw manifest bytes.
func buildTestManifest(
	t *testing.T, store *Store,
) (digest.Digest, []byte) {
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

	// Push: local store → remote (memory)
	localStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	manifestDigest, _ := buildTestManifest(t, localStore)

	reg := newTestRegistry(t, remoteStore)
	ref := "example.com/myorg/my-skill:v1.0.0"

	err = reg.Push(ctx, localStore, manifestDigest, ref)
	require.NoError(t, err)

	// Pull: remote (memory) → new local store
	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	pulledDigest, err := reg.Pull(ctx, pullStore, ref)
	require.NoError(t, err)
	assert.Equal(t, manifestDigest, pulledDigest)

	// Verify manifest was stored locally
	got, err := pullStore.GetManifest(ctx, pulledDigest)
	require.NoError(t, err)
	assert.NotEmpty(t, got)

	// Verify we can resolve the tag
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

	// Build an image index referencing the manifest
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
	assert.True(t, isIdx, "pulled artifact should be an index")

	// Verify the index contents
	pulledIndex, err := pullStore.GetIndex(ctx, pulledDigest)
	require.NoError(t, err)
	require.Len(t, pulledIndex.Manifests, 1)
	assert.Equal(t, manifestDigest.String(), pulledIndex.Manifests[0].Digest)

	// Verify the manifest is also present
	pulledManifest, err := pullStore.GetManifest(ctx, manifestDigest)
	require.NoError(t, err)
	assert.NotEmpty(t, pulledManifest)

	// Verify tag resolution
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

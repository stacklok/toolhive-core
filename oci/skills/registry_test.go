// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
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
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeSkill,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configContent)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
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

	index := ocispec.Index{
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: ArtifactTypeSkill,
		Manifests: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestBytes)),
				Platform:  &ocispec.Platform{OS: OSLinux, Architecture: ArchAMD64},
			},
		},
	}
	index.SchemaVersion = 2

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
	assert.Equal(t, manifestDigest, pulledIndex.Manifests[0].Digest)

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

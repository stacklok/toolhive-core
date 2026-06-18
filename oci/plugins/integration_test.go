// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"

	"github.com/stacklok/toolhive-core/oci/artifact"
)

// TestIntegration_PackagePushPull exercises the full e2e flow:
// package a plugin → push to an in-memory registry → pull into a fresh store →
// verify all content (index, manifests, config, layer, tags, extracted files).
func TestIntegration_PackagePushPull(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	ref := "example.com/myorg/integration-plugin:v1.0.0"

	// --- Setup: create a plugin directory with components ---
	pluginDir := createTestPluginDir(t)

	// --- Phase 1: Package ---
	packageStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(packageStore)
	opts := PackageOptions{Epoch: time.Unix(1000000, 0).UTC()}

	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	assert.Equal(t, testPluginName, result.Config.Name)
	assert.Equal(t, "A test plugin for packaging", result.Config.Description)
	assert.Equal(t, "1.0.0", result.Config.Version)
	assert.Equal(t, "Apache-2.0", result.Config.License)
	assert.Contains(t, result.Config.Files, ManifestFileName)
	assert.Contains(t, result.Config.Files, "commands/test.md")
	assert.Equal(t, artifact.DefaultPlatforms, result.Platforms)

	// Verify the index was stored and is well-formed
	isIdx, err := packageStore.IsIndex(ctx, result.IndexDigest)
	require.NoError(t, err)
	assert.True(t, isIdx, "packaged artifact should be an index")

	idx, err := packageStore.GetIndex(ctx, result.IndexDigest)
	require.NoError(t, err)
	assert.Equal(t, ocispec.MediaTypeImageIndex, idx.MediaType)
	assert.Equal(t, ArtifactTypePlugin, idx.ArtifactType)
	require.Len(t, idx.Manifests, len(artifact.DefaultPlatforms))

	// --- Phase 2: Push to in-memory registry ---
	remoteStore := memory.New()
	reg := &Registry{
		newTarget: func(_ registry.Reference) (oras.Target, error) {
			return remoteStore, nil
		},
	}

	err = reg.Push(ctx, packageStore, result.IndexDigest, ref)
	require.NoError(t, err)

	// Verify the remote has the content tagged
	remoteDesc, err := remoteStore.Resolve(ctx, "v1.0.0")
	require.NoError(t, err)
	assert.Equal(t, result.IndexDigest, remoteDesc.Digest)

	// --- Phase 3: Pull into a fresh store ---
	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	pulledDigest, err := reg.Pull(ctx, pullStore, ref)
	require.NoError(t, err)
	assert.Equal(t, result.IndexDigest, pulledDigest, "pulled digest should match packaged index digest")

	// --- Phase 4: Verify pulled content ---

	// 4a. Tag resolution
	resolved, err := pullStore.Resolve(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, pulledDigest, resolved)

	// 4b. Index is intact
	pulledIdx, err := pullStore.GetIndex(ctx, pulledDigest)
	require.NoError(t, err)
	assert.Equal(t, ocispec.MediaTypeImageIndex, pulledIdx.MediaType)
	assert.Equal(t, ArtifactTypePlugin, pulledIdx.ArtifactType)
	require.Len(t, pulledIdx.Manifests, len(artifact.DefaultPlatforms))

	// 4c. Each platform manifest, config, and layer are present and correct
	for _, desc := range pulledIdx.Manifests {
		require.NotNil(t, desc.Platform)
		platformStr := desc.Platform.OS + "/" + desc.Platform.Architecture

		// Manifest
		manifestBytes, err := pullStore.GetManifest(ctx, desc.Digest)
		require.NoError(t, err, "manifest for %s should be present", platformStr)

		var manifest ocispec.Manifest
		require.NoError(t, json.Unmarshal(manifestBytes, &manifest))

		assert.Equal(t, ocispec.MediaTypeImageManifest, manifest.MediaType)
		assert.Equal(t, ArtifactTypePlugin, manifest.ArtifactType)
		assert.Equal(t, testPluginName, manifest.Annotations[AnnotationPluginName])
		assert.Equal(t, "1.0.0", manifest.Annotations[AnnotationPluginVersion])
		require.Len(t, manifest.Layers, 1)

		// Config
		configBytes, err := pullStore.GetBlob(ctx, manifest.Config.Digest)
		require.NoError(t, err, "config for %s should be present", platformStr)

		var ociConfig ocispec.Image
		require.NoError(t, json.Unmarshal(configBytes, &ociConfig))

		assert.Equal(t, desc.Platform.OS, ociConfig.OS)
		assert.Equal(t, desc.Platform.Architecture, ociConfig.Architecture)

		labels := ociConfig.Config.Labels
		require.NotNil(t, labels)
		assert.Equal(t, testPluginName, labels[LabelPluginName])
		assert.Equal(t, "1.0.0", labels[LabelPluginVersion])

		config, err := PluginConfigFromImageConfig(&ociConfig)
		require.NoError(t, err)
		assert.Equal(t, testPluginName, config.Name)
		assert.Equal(t, []string{testRequireServerV1, testRequireSkillV1}, config.Requires)

		// Layer — extract and verify files
		layerBytes, err := pullStore.GetBlob(ctx, manifest.Layers[0].Digest)
		require.NoError(t, err, "layer for %s should be present", platformStr)

		files, err := artifact.DecompressTar(layerBytes)
		require.NoError(t, err)

		fileMap := make(map[string][]byte, len(files))
		for _, f := range files {
			fileMap[f.Path] = f.Content
		}

		// Verify the plugin manifest is present and has correct content
		manifestJSON, ok := fileMap[ManifestFileName]
		require.True(t, ok, "%s should be in the layer", ManifestFileName)
		assert.Contains(t, string(manifestJSON), testPluginName)

		// Verify a component file is present
		command, ok := fileMap["commands/test.md"]
		require.True(t, ok, "commands/test.md should be in the layer")
		assert.Contains(t, string(command), "Test Command")
	}
}

// TestIntegration_PushPull_TwoVersions verifies that pushing two versions
// of the same plugin and pulling them both results in correct content.
func TestIntegration_PushPull_TwoVersions(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	remoteStore := memory.New()
	reg := &Registry{
		newTarget: func(_ registry.Reference) (oras.Target, error) {
			return remoteStore, nil
		},
	}

	// Package and push v1
	v1Dir := createVersionedPluginDir(t, "1.0.0")
	v1Store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	v1Result, err := NewPackager(v1Store).Package(ctx, v1Dir, PackageOptions{
		Epoch: time.Unix(1000, 0).UTC(),
	})
	require.NoError(t, err)

	ref1 := "example.com/myorg/versioned-plugin:v1.0.0"
	err = reg.Push(ctx, v1Store, v1Result.IndexDigest, ref1)
	require.NoError(t, err)

	// Package and push v2
	v2Dir := createVersionedPluginDir(t, "2.0.0")
	v2Store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	v2Result, err := NewPackager(v2Store).Package(ctx, v2Dir, PackageOptions{
		Epoch: time.Unix(2000, 0).UTC(),
	})
	require.NoError(t, err)

	ref2 := "example.com/myorg/versioned-plugin:v2.0.0"
	err = reg.Push(ctx, v2Store, v2Result.IndexDigest, ref2)
	require.NoError(t, err)

	// Digests should differ
	assert.NotEqual(t, v1Result.IndexDigest, v2Result.IndexDigest)

	// Pull both into the same store
	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	pulledV1, err := reg.Pull(ctx, pullStore, ref1)
	require.NoError(t, err)
	assert.Equal(t, v1Result.IndexDigest, pulledV1)

	pulledV2, err := reg.Pull(ctx, pullStore, ref2)
	require.NoError(t, err)
	assert.Equal(t, v2Result.IndexDigest, pulledV2)

	// Both tags resolve correctly in the same store
	resolvedV1, err := pullStore.Resolve(ctx, ref1)
	require.NoError(t, err)
	assert.Equal(t, pulledV1, resolvedV1)

	resolvedV2, err := pullStore.Resolve(ctx, ref2)
	require.NoError(t, err)
	assert.Equal(t, pulledV2, resolvedV2)

	// Verify version annotations on each
	for _, tc := range []struct {
		dig     digest.Digest
		version string
	}{
		{pulledV1, "1.0.0"},
		{pulledV2, "2.0.0"},
	} {
		idx, err := pullStore.GetIndex(ctx, tc.dig)
		require.NoError(t, err)
		assert.Equal(t, tc.version, idx.Annotations[AnnotationPluginVersion])
	}
}

// TestIntegration_PullPreservesBlobs verifies that after a pull, the pulled
// blobs can be used to reconstruct the original plugin content byte-for-byte.
func TestIntegration_PullPreservesBlobs(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	remoteStore := memory.New()
	reg := &Registry{
		newTarget: func(_ registry.Reference) (oras.Target, error) {
			return remoteStore, nil
		},
	}

	pluginDir := createTestPluginDir(t)
	packageStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}
	result, err := NewPackager(packageStore).Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	ref := "example.com/myorg/blob-test:v1.0.0"
	err = reg.Push(ctx, packageStore, result.IndexDigest, ref)
	require.NoError(t, err)

	pullStore, err := NewStore(t.TempDir())
	require.NoError(t, err)

	_, err = reg.Pull(ctx, pullStore, ref)
	require.NoError(t, err)

	// Get the original layer bytes from the package store
	originalLayer, err := packageStore.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	// Get the pulled layer bytes
	pulledLayer, err := pullStore.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	assert.Equal(t, originalLayer, pulledLayer, "layer content should be byte-for-byte identical after pull")

	// Same for config
	originalConfig, err := packageStore.GetBlob(ctx, result.ConfigDigest)
	require.NoError(t, err)

	pulledConfig, err := pullStore.GetBlob(ctx, result.ConfigDigest)
	require.NoError(t, err)

	assert.Equal(t, originalConfig, pulledConfig, "config content should be byte-for-byte identical after pull")
}

// --- integration test helpers ---

// createVersionedPluginDir creates a plugin directory with the given version.
func createVersionedPluginDir(t *testing.T, version string) string {
	t.Helper()

	dir := t.TempDir()
	writeManifest(t, dir, `{"name":"versioned-plugin","description":"Versioned plugin","version":"`+version+`"}`)
	return dir
}

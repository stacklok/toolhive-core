// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/oci/artifact"
)

const testPluginName = "test-plugin"

func TestPackager_Package(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	result, err := packager.Package(context.Background(), pluginDir, opts)
	require.NoError(t, err)

	assert.NotEmpty(t, result.ManifestDigest.String())
	assert.NotEmpty(t, result.ConfigDigest.String())
	assert.NotEmpty(t, result.LayerDigest.String())
	assert.NotEmpty(t, result.IndexDigest.String())

	assert.Equal(t, testPluginName, result.Config.Name)
	assert.Equal(t, "A test plugin for packaging", result.Config.Description)
	assert.Equal(t, "1.0.0", result.Config.Version)
	assert.Equal(t, "Apache-2.0", result.Config.License)
	assert.Contains(t, result.Config.Files, ManifestFileName)
	assert.Contains(t, result.Config.Files, "commands/test.md")
	assert.Equal(t, ComponentInventory{testComponentCommands: 1, "agents": 1, "skills": 1, "hooks": 1, "mcpServers": 1}, result.Config.Components)
	assert.Equal(t, []string{"ghcr.io/org/server:v1", "ghcr.io/org/skill:v1"}, result.Config.Requires)
}

func TestPackager_Package_Reproducible(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	store1, err := NewStore(t.TempDir())
	require.NoError(t, err)

	store2, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	result1, err := NewPackager(store1).Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	result2, err := NewPackager(store2).Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	assert.Equal(t, result1.IndexDigest, result2.IndexDigest, "IndexDigest not reproducible")
	assert.Equal(t, result1.ManifestDigest, result2.ManifestDigest, "ManifestDigest not reproducible")
	assert.Equal(t, result1.ConfigDigest, result2.ConfigDigest, "ConfigDigest not reproducible")
	assert.Equal(t, result1.LayerDigest, result2.LayerDigest, "LayerDigest not reproducible")
}

func TestPackager_Package_Reproducible_SourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1234567890")

	pluginDir := createTestPluginDir(t)
	ctx := context.Background()

	store1, err := NewStore(t.TempDir())
	require.NoError(t, err)
	result1, err := NewPackager(store1).Package(ctx, pluginDir, DefaultPackageOptions())
	require.NoError(t, err)

	store2, err := NewStore(t.TempDir())
	require.NoError(t, err)
	result2, err := NewPackager(store2).Package(ctx, pluginDir, DefaultPackageOptions())
	require.NoError(t, err)

	assert.Equal(t, result1.IndexDigest, result2.IndexDigest)
	assert.Equal(t, result1.ManifestDigest, result2.ManifestDigest)
	assert.Equal(t, result1.ConfigDigest, result2.ConfigDigest)
	assert.Equal(t, result1.LayerDigest, result2.LayerDigest)
}

func TestPackager_Package_VerifyManifest(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	manifestBytes, err := store.GetManifest(ctx, result.ManifestDigest)
	require.NoError(t, err)

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(manifestBytes, &manifest))

	assert.Equal(t, 2, manifest.SchemaVersion)
	assert.Equal(t, ocispec.MediaTypeImageManifest, manifest.MediaType)
	assert.Equal(t, ArtifactTypePlugin, manifest.ArtifactType)
	assert.Equal(t, ocispec.MediaTypeImageConfig, manifest.Config.MediaType)
	require.Len(t, manifest.Layers, 1)
	assert.Equal(t, ocispec.MediaTypeImageLayerGzip, manifest.Layers[0].MediaType)
	assert.Equal(t, "plugin.tar.gz", manifest.Layers[0].Annotations[ocispec.AnnotationTitle])
	assert.Equal(t, testPluginName, manifest.Annotations[AnnotationPluginName])
	assert.Equal(t, "Apache-2.0", manifest.Annotations[AnnotationPluginLicense])
	assert.JSONEq(t, testPluginComponents, manifest.Annotations[AnnotationPluginComponents])
	assert.JSONEq(t, `["ghcr.io/org/server:v1","ghcr.io/org/skill:v1"]`, manifest.Annotations[AnnotationPluginRequires])
}

func TestPackager_Package_VerifyLayer(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	layerBytes, err := store.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	files, err := artifact.DecompressTar(layerBytes)
	require.NoError(t, err)

	fileMap := make(map[string][]byte, len(files))
	for _, f := range files {
		fileMap[f.Path] = f.Content
	}

	_, ok := fileMap[ManifestFileName]
	assert.True(t, ok, "plugin manifest not found in layer")
	_, ok = fileMap["commands/test.md"]
	assert.True(t, ok, "commands/test.md not found in layer")
	_, ok = fileMap[".mcp.json"]
	assert.True(t, ok, ".mcp.json should be packaged verbatim")
	_, ok = fileMap[".hidden"]
	assert.False(t, ok, "hidden file should not be in layer")
}

func TestPackager_Package_VerifyOCIConfig(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	configBytes, err := store.GetBlob(ctx, result.ConfigDigest)
	require.NoError(t, err)

	var ociConfig ocispec.Image
	require.NoError(t, json.Unmarshal(configBytes, &ociConfig))

	assert.Equal(t, artifact.ArchAMD64, ociConfig.Architecture)
	assert.Equal(t, artifact.OSLinux, ociConfig.OS)
	assert.NotNil(t, ociConfig.Created, "top-level created field should be set")
	assert.Equal(t, "layers", ociConfig.RootFS.Type)
	require.Len(t, ociConfig.RootFS.DiffIDs, 1)
	assert.Contains(t, ociConfig.RootFS.DiffIDs[0].String(), "sha256:")

	labels := ociConfig.Config.Labels
	require.NotNil(t, labels)
	assert.Equal(t, testPluginName, labels[LabelPluginName])
	assert.Equal(t, "A test plugin for packaging", labels[LabelPluginDescription])
	assert.Equal(t, "1.0.0", labels[LabelPluginVersion])
	assert.JSONEq(t, testPluginComponents, labels[LabelPluginComponents])

	cfg, err := PluginConfigFromImageConfig(&ociConfig)
	require.NoError(t, err)
	assert.Equal(t, result.Config, cfg)

	require.Len(t, ociConfig.History, 1)
	assert.Equal(t, "toolhive package", ociConfig.History[0].CreatedBy)
}

func TestPackager_Package_MultiPlatformConfigMatch(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	platforms := []ocispec.Platform{
		{OS: artifact.OSLinux, Architecture: artifact.ArchAMD64},
		{OS: artifact.OSLinux, Architecture: artifact.ArchARM64},
	}
	opts := PackageOptions{
		Epoch:     time.Unix(0, 0).UTC(),
		Platforms: platforms,
	}

	ctx := context.Background()
	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	assert.Equal(t, platforms, result.Platforms)

	indexBytes, err := store.GetManifest(ctx, result.IndexDigest)
	require.NoError(t, err)

	var index ocispec.Index
	require.NoError(t, json.Unmarshal(indexBytes, &index))

	require.Len(t, index.Manifests, 2)

	for _, descriptor := range index.Manifests {
		require.NotNil(t, descriptor.Platform)
		platformStr := descriptor.Platform.OS + "/" + descriptor.Platform.Architecture

		manifestBytes, err := store.GetManifest(ctx, descriptor.Digest)
		require.NoError(t, err)

		var manifest ocispec.Manifest
		require.NoError(t, json.Unmarshal(manifestBytes, &manifest))

		configBytes, err := store.GetBlob(ctx, manifest.Config.Digest)
		require.NoError(t, err)

		var ociConfig ocispec.Image
		require.NoError(t, json.Unmarshal(configBytes, &ociConfig))

		assert.Equal(t, descriptor.Platform.OS, ociConfig.OS,
			"Config OS for platform %s", platformStr)
		assert.Equal(t, descriptor.Platform.Architecture, ociConfig.Architecture,
			"Config Architecture for platform %s", platformStr)
	}
}

func TestDefaultPackageOptions(t *testing.T) {
	t.Parallel()

	opts := DefaultPackageOptions()
	assert.False(t, opts.Epoch.IsZero())
	assert.Equal(t, artifact.DefaultPlatforms, opts.Platforms)
}

func TestDefaultPackageOptions_WithSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1234567890")

	opts := DefaultPackageOptions()
	expected := time.Unix(1234567890, 0).UTC()
	assert.True(t, opts.Epoch.Equal(expected))
}

func TestPackager_Package_MissingManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ManifestFileName+" not found")
	assert.ErrorIs(t, err, ErrPluginManifestMissing)
}

func TestPackager_Package_MissingName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifest(t, dir, `{"description":"A plugin without a name","version":"1.0.0"}`)

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plugin name is required")
	assert.ErrorIs(t, err, ErrInvalidPluginManifest)
}

func TestPackager_Package_DefaultPlatforms(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	result, err := packager.Package(context.Background(), pluginDir, opts)
	require.NoError(t, err)

	assert.Equal(t, artifact.DefaultPlatforms, result.Platforms)
}

func TestPackager_Package_RejectsSymlinks(t *testing.T) {
	t.Parallel()

	dir := createTestPluginDir(t)
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(dir, "evil_link")))

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
	assert.ErrorIs(t, err, ErrInvalidPluginFile)
}

func TestPackager_Package_RejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()

	dir := createTestPluginDir(t)
	require.NoError(t, os.Symlink("/etc", filepath.Join(dir, "evil_dir")))

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
	assert.ErrorIs(t, err, ErrInvalidPluginFile)
}

func TestNewPackager_NilStore(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		NewPackager(nil)
	})
}

func TestPackager_Package_InvalidManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    testNameInvalidJSON,
			content: `{"name":`,
		},
		{
			name:    "oversized manifest",
			content: `{"name":"test","x":"` + string(bytes.Repeat([]byte("a"), maxManifestSize+1)) + `"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			writeManifest(t, dir, tt.content)

			store, err := NewStore(t.TempDir())
			require.NoError(t, err)

			packager := NewPackager(store)
			opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

			_, err = packager.Package(context.Background(), dir, opts)
			assert.Error(t, err)
			assert.ErrorIs(t, err, ErrInvalidPluginManifest)
		})
	}
}

func TestPackager_Package_NonexistentDir(t *testing.T) {
	t.Parallel()

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), "/nonexistent/path", opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "plugin directory not found")
	assert.ErrorIs(t, err, ErrInvalidPluginDir)
}

func TestPackager_Package_IndexStructure(t *testing.T) {
	t.Parallel()

	pluginDir := createTestPluginDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, pluginDir, opts)
	require.NoError(t, err)

	indexBytes, err := store.GetManifest(ctx, result.IndexDigest)
	require.NoError(t, err)

	var index ocispec.Index
	require.NoError(t, json.Unmarshal(indexBytes, &index))

	assert.Equal(t, 2, index.SchemaVersion)
	assert.Equal(t, ocispec.MediaTypeImageIndex, index.MediaType)
	assert.Equal(t, ArtifactTypePlugin, index.ArtifactType)
	assert.NotEmpty(t, index.Annotations)
	assert.Equal(t, testPluginName, index.Annotations[AnnotationPluginName])
}

func TestParseManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    *pluginManifest
		wantErr bool
	}{
		{
			name: "full manifest",
			content: `{
	"name":"my-plugin",
	"description":"A great plugin",
	"version":"2.0.0",
	"license":"MIT",
	"commands":{"hello":"commands/hello.md"}
}`,
			want: &pluginManifest{
				Name:        testPluginMyPlugin,
				Description: "A great plugin",
				Version:     "2.0.0",
				License:     "MIT",
			},
		},
		{
			name:    testNameInvalidJSON,
			content: "not json",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pm, err := parseManifest([]byte(tt.content))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Name, pm.Name)
			assert.Equal(t, tt.want.Description, pm.Description)
			assert.Equal(t, tt.want.Version, pm.Version)
			assert.Equal(t, tt.want.License, pm.License)
		})
	}
}

func TestCollectPluginFiles_ExceedsMaxFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifest(t, dir, `{"name":"too-many-files","description":"A plugin with too many files","version":"1.0.0"}`)

	// Create maxPluginFiles + 1 extra files (plugin.json is excluded from the count).
	for i := range maxPluginFiles + 1 {
		name := filepath.Join(dir, fmt.Sprintf("file_%05d.txt", i))
		require.NoError(t, os.WriteFile(name, []byte("x"), 0600))
	}

	_, err := collectPluginFiles(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
	assert.ErrorIs(t, err, ErrTooManyFiles)
}

func TestPackager_Package_SentinelErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(t *testing.T) string
		wantErr error
	}{
		{
			name: "missing plugin directory",
			setup: func(t *testing.T) string {
				t.Helper()
				return filepath.Join(t.TempDir(), "does-not-exist")
			},
			wantErr: ErrInvalidPluginDir,
		},
		{
			name: "path is file not directory",
			setup: func(t *testing.T) string {
				t.Helper()
				f := filepath.Join(t.TempDir(), "not-a-dir")
				require.NoError(t, os.WriteFile(f, []byte("x"), 0600))
				return f
			},
			wantErr: ErrInvalidPluginDir,
		},
		{
			name: "path contains traversal",
			setup: func(_ *testing.T) string {
				return "../no-such-plugin-dir"
			},
			wantErr: ErrInvalidPluginDir,
		},
		{
			name: "missing plugin manifest",
			setup: func(t *testing.T) string {
				t.Helper()
				return t.TempDir()
			},
			wantErr: ErrPluginManifestMissing,
		},
		{
			name: "manifest invalid JSON",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				writeManifest(t, dir, `{"name":`)
				return dir
			},
			wantErr: ErrInvalidPluginManifest,
		},
		{
			name: "manifest missing name",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := t.TempDir()
				writeManifest(t, dir, `{"description":"nameless plugin"}`)
				return dir
			},
			wantErr: ErrInvalidPluginManifest,
		},
		{
			name: "symlinked file in plugin directory",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := createTestPluginDir(t)
				require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(dir, "evil_link")))
				return dir
			},
			wantErr: ErrInvalidPluginFile,
		},
		{
			name: "symlinked directory in plugin directory",
			setup: func(t *testing.T) string {
				t.Helper()
				dir := createTestPluginDir(t)
				require.NoError(t, os.Symlink("/etc", filepath.Join(dir, "evil_dir")))
				return dir
			},
			wantErr: ErrInvalidPluginFile,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			store, err := NewStore(t.TempDir())
			require.NoError(t, err)

			_, err = NewPackager(store).Package(context.Background(), tt.setup(t), PackageOptions{})
			require.Error(t, err)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func createTestPluginDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	writeManifest(t, dir, `{
  "name": "test-plugin",
  "description": "A test plugin for packaging",
  "version": "1.0.0",
  "license": "Apache-2.0",
  "commands": {"test": "commands/test.md"},
  "agents": ["agents/reviewer.md"],
  "skills": ["skills/foo"],
  "hooks": {"PreToolUse": [{"command": "scripts/hook.sh"}]},
  "mcpServers": {"srv": {"command": "node", "args": ["server.js"]}},
  "dependencies": ["ghcr.io/org/skill:v1"],
  "requires": ["ghcr.io/org/server:v1"]
}`)
	writeFile(t, dir, "commands/test.md", "# Test Command\n")
	writeFile(t, dir, "agents/reviewer.md", "# Reviewer\n")
	writeFile(t, dir, "skills/foo/SKILL.md", "---\nname: foo\n---\n# Foo\n")
	writeFile(t, dir, "scripts/hook.sh", "#!/bin/sh\necho hook\n")
	writeFile(t, dir, ".mcp.json", `{"mcpServers":{"srv":{"command":"node","args":["server.js"]}}}`)
	writeFile(t, dir, ".hidden", "hidden\n")
	return dir
}

func writeManifest(t *testing.T, dir, content string) {
	t.Helper()
	writeFile(t, dir, ManifestFileName, content)
}

func writeFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(relPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0750))
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

// TestPackager_Package_PreservesFileMode verifies that an executable file's
// permission bits survive packaging rather than being flattened to 0644.
func TestPackager_Package_PreservesFileMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeManifest(t, dir, `{
  "name": "test-plugin",
  "description": "plugin with an executable hook",
  "version": "1.0.0",
  "hooks": {"PreToolUse": [{"command": "scripts/hook.sh"}]}
}`)
	scriptPath := filepath.Join(dir, "scripts", "hook.sh")
	require.NoError(t, os.MkdirAll(filepath.Dir(scriptPath), 0750))
	require.NoError(t, os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hook\n"), 0700)) //#nosec G306 -- test fixture must be executable

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	result, err := NewPackager(store).Package(ctx, dir, PackageOptions{Epoch: time.Unix(0, 0).UTC()})
	require.NoError(t, err)

	layerBytes, err := store.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	files, err := artifact.DecompressTar(layerBytes)
	require.NoError(t, err)

	var found bool
	for _, f := range files {
		if f.Path == "scripts/hook.sh" {
			found = true
			assert.Equal(t, int64(0700), f.Mode&0777, "executable bit should be preserved in the layer")
		}
	}
	assert.True(t, found, "scripts/hook.sh not found in layer")
}

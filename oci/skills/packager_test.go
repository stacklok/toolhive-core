// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSkillName = "test-skill"

func TestPackager_Package(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	result, err := packager.Package(context.Background(), skillDir, opts)
	require.NoError(t, err)

	assert.NotEmpty(t, result.ManifestDigest.String())
	assert.NotEmpty(t, result.ConfigDigest.String())
	assert.NotEmpty(t, result.LayerDigest.String())
	assert.NotEmpty(t, result.IndexDigest.String())

	assert.Equal(t, testSkillName, result.Config.Name)
	assert.Equal(t, "A test skill for packaging", result.Config.Description)
	assert.Equal(t, "1.0.0", result.Config.Version)
	assert.NotEmpty(t, result.Config.Files)
}

func TestPackager_Package_Reproducible(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	store1, err := NewStore(t.TempDir())
	require.NoError(t, err)

	store2, err := NewStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()

	result1, err := NewPackager(store1).Package(ctx, skillDir, opts)
	require.NoError(t, err)

	result2, err := NewPackager(store2).Package(ctx, skillDir, opts)
	require.NoError(t, err)

	assert.Equal(t, result1.IndexDigest, result2.IndexDigest, "IndexDigest not reproducible")
	assert.Equal(t, result1.ManifestDigest, result2.ManifestDigest, "ManifestDigest not reproducible")
	assert.Equal(t, result1.ConfigDigest, result2.ConfigDigest, "ConfigDigest not reproducible")
	assert.Equal(t, result1.LayerDigest, result2.LayerDigest, "LayerDigest not reproducible")
}

func TestPackager_Package_VerifyManifest(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	manifestBytes, err := store.GetManifest(ctx, result.ManifestDigest)
	require.NoError(t, err)

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(manifestBytes, &manifest))

	assert.Equal(t, 2, manifest.SchemaVersion)
	assert.Equal(t, ocispec.MediaTypeImageManifest, manifest.MediaType)
	assert.Equal(t, ArtifactTypeSkill, manifest.ArtifactType)
	assert.Equal(t, ocispec.MediaTypeImageConfig, manifest.Config.MediaType)
	require.Len(t, manifest.Layers, 1)
	assert.Equal(t, ocispec.MediaTypeImageLayerGzip, manifest.Layers[0].MediaType)
	assert.Equal(t, testSkillName, manifest.Annotations[AnnotationSkillName])
}

func TestPackager_Package_VerifyLayer(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	layerBytes, err := store.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	files, err := DecompressTar(layerBytes)
	require.NoError(t, err)

	found := false
	for _, f := range files {
		if f.Path == "SKILL.md" {
			found = true
			break
		}
	}
	assert.True(t, found, "SKILL.md not found in layer")
}

func TestPackager_Package_WithScripts(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDirWithScripts(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	assert.Contains(t, result.Config.Files, "scripts/run.sh")

	layerBytes, err := store.GetBlob(ctx, result.LayerDigest)
	require.NoError(t, err)

	files, err := DecompressTar(layerBytes)
	require.NoError(t, err)

	hasScript := false
	for _, f := range files {
		if f.Path == "scripts/run.sh" {
			hasScript = true
			break
		}
	}
	assert.True(t, hasScript, "scripts/run.sh not found in layer")
}

func TestPackager_Package_VerifyOCIConfig(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	configBytes, err := store.GetBlob(ctx, result.ConfigDigest)
	require.NoError(t, err)

	var ociConfig ocispec.Image
	require.NoError(t, json.Unmarshal(configBytes, &ociConfig))

	assert.Equal(t, "amd64", ociConfig.Architecture)
	assert.Equal(t, "linux", ociConfig.OS)
	assert.NotNil(t, ociConfig.Created, "top-level created field should be set")
	assert.Equal(t, "layers", ociConfig.RootFS.Type)
	require.Len(t, ociConfig.RootFS.DiffIDs, 1)
	assert.Contains(t, ociConfig.RootFS.DiffIDs[0].String(), "sha256:")

	labels := ociConfig.Config.Labels
	require.NotNil(t, labels)
	assert.Equal(t, testSkillName, labels[LabelSkillName])
	assert.Equal(t, "A test skill for packaging", labels[LabelSkillDescription])
	assert.Equal(t, "1.0.0", labels[LabelSkillVersion])

	var allowedTools []string
	require.NoError(t, json.Unmarshal([]byte(labels[LabelSkillAllowedTools]), &allowedTools))
	assert.Equal(t, []string{"Read", "Grep"}, allowedTools)

	require.Len(t, ociConfig.History, 1)
	assert.Equal(t, "toolhive package", ociConfig.History[0].CreatedBy)
}

func TestPackager_Package_MultiPlatformConfigMatch(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	platforms := []Platform{
		{OS: "linux", Architecture: "amd64"},
		{OS: "linux", Architecture: "arm64"},
	}
	opts := PackageOptions{
		Epoch:     time.Unix(0, 0).UTC(),
		Platforms: platforms,
	}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	assert.Equal(t, platforms, result.Platforms)

	// Get the index
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
	assert.Equal(t, DefaultPlatforms, opts.Platforms)
}

func TestDefaultPackageOptions_WithSourceDateEpoch(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "1234567890")

	opts := DefaultPackageOptions()
	expected := time.Unix(1234567890, 0).UTC()
	assert.True(t, opts.Epoch.Equal(expected))
}

func TestPackager_Package_MissingSkillMD(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SKILL.md not found")
}

func TestPackager_Package_MissingName(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	skillMD := `---
description: A skill without a name
version: 1.0.0
---
# No Name Skill
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0600))

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "skill name is required")
}

func TestPackager_Package_DefaultPlatforms(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	result, err := packager.Package(context.Background(), skillDir, opts)
	require.NoError(t, err)

	assert.Equal(t, DefaultPlatforms, result.Platforms)
}

func TestPackager_Package_RejectsSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	skillMD := `---
name: test-skill
description: A test skill
version: 1.0.0
---
# Test Skill
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0600))
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(dir, "evil_link")))

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
}

func TestPackager_Package_RejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	skillMD := `---
name: test-skill
description: A test skill
version: 1.0.0
---
# Test Skill
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0600))
	require.NoError(t, os.Symlink("/etc", filepath.Join(dir, "evil_dir")))

	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	_, err = packager.Package(context.Background(), dir, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "symlinks not allowed")
}

func TestNewPackager_NilStore(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		NewPackager(nil)
	})
}

func TestPackager_Package_InvalidFrontmatter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "no frontmatter",
			content: "# Just markdown\nNo frontmatter here.",
			wantErr: "must start with YAML frontmatter",
		},
		{
			name:    "unclosed frontmatter",
			content: "---\nname: test\n# Never closed",
			wantErr: "missing closing delimiter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(tt.content), 0600))

			store, err := NewStore(t.TempDir())
			require.NoError(t, err)

			packager := NewPackager(store)
			opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

			_, err = packager.Package(context.Background(), dir, opts)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
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
	assert.Contains(t, err.Error(), "skill directory not found")
}

func TestPackager_Package_IndexStructure(t *testing.T) {
	t.Parallel()

	skillDir := createTestSkillDir(t)
	store, err := NewStore(t.TempDir())
	require.NoError(t, err)

	packager := NewPackager(store)
	opts := PackageOptions{Epoch: time.Unix(0, 0).UTC()}

	ctx := context.Background()
	result, err := packager.Package(ctx, skillDir, opts)
	require.NoError(t, err)

	indexBytes, err := store.GetManifest(ctx, result.IndexDigest)
	require.NoError(t, err)

	var index ocispec.Index
	require.NoError(t, json.Unmarshal(indexBytes, &index))

	assert.Equal(t, 2, index.SchemaVersion)
	assert.Equal(t, ocispec.MediaTypeImageIndex, index.MediaType)
	assert.Equal(t, ArtifactTypeSkill, index.ArtifactType)
	assert.NotEmpty(t, index.Annotations)
	assert.Equal(t, testSkillName, index.Annotations[AnnotationSkillName])
}

func TestParseFrontmatter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    *frontmatter
		wantErr bool
	}{
		{
			name: "full frontmatter",
			content: `---
name: my-skill
description: A great skill
version: 2.0.0
allowed-tools:
  - Read
  - Write
license: MIT
---
# Body`,
			want: &frontmatter{
				Name:         "my-skill",
				Description:  "A great skill",
				Version:      "2.0.0",
				AllowedTools: stringOrSlice{"Read", "Write"},
				License:      "MIT",
			},
		},
		{
			name: "allowed-tools as space-delimited string",
			content: `---
name: my-skill
description: A skill
allowed-tools: Read Grep Glob
---
# Body`,
			want: &frontmatter{
				Name:         "my-skill",
				Description:  "A skill",
				AllowedTools: stringOrSlice{"Read", "Grep", "Glob"},
			},
		},
		{
			name: "allowed-tools as comma-delimited string",
			content: `---
name: my-skill
description: A skill
allowed-tools: Read, Grep, Glob
---
# Body`,
			want: &frontmatter{
				Name:         "my-skill",
				Description:  "A skill",
				AllowedTools: stringOrSlice{"Read", "Grep", "Glob"},
			},
		},
		{
			name:    "no frontmatter delimiters",
			content: "just markdown",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fm, err := parseFrontmatter([]byte(tt.content))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.Name, fm.Name)
			assert.Equal(t, tt.want.Description, fm.Description)
			assert.Equal(t, tt.want.Version, fm.Version)
			assert.Equal(t, []string(tt.want.AllowedTools), []string(fm.AllowedTools))
			assert.Equal(t, tt.want.License, fm.License)
		})
	}
}

// Helper functions

func createTestSkillDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()

	skillMD := `---
name: test-skill
description: A test skill for packaging
version: 1.0.0
allowed-tools:
  - Read
  - Grep
---
# Test Skill

This is a test skill.
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0600))

	return dir
}

func createTestSkillDirWithScripts(t *testing.T) string {
	t.Helper()

	dir := createTestSkillDir(t)

	scriptsDir := filepath.Join(dir, "scripts")
	require.NoError(t, os.MkdirAll(scriptsDir, 0750))

	script := `#!/bin/bash
echo "Hello from test skill"
`
	require.NoError(t, os.WriteFile(filepath.Join(scriptsDir, "run.sh"), []byte(script), 0600))

	return dir
}

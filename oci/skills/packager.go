// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v3"
)

// Packager creates reproducible OCI artifacts from skill directories.
type Packager struct {
	store *Store
}

// manifestInfo holds a manifest digest along with its size.
type manifestInfo struct {
	digest digest.Digest
	size   int64
}

// frontmatter represents the YAML frontmatter in a SKILL.md file.
type frontmatter struct {
	Name          string            `yaml:"name"`
	Description   string            `yaml:"description"`
	Version       string            `yaml:"version,omitempty"`
	AllowedTools  stringOrSlice     `yaml:"allowed-tools,omitempty"`
	License       string            `yaml:"license,omitempty"`
	Compatibility string            `yaml:"compatibility,omitempty"`
	Metadata      map[string]string `yaml:"metadata,omitempty"`
}

// stringOrSlice is a YAML type that can unmarshal from a string or a sequence.
type stringOrSlice []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *stringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		str := value.Value
		if str == "" {
			*s = nil
			return nil
		}
		var parts []string
		if strings.Contains(str, ",") {
			parts = strings.Split(str, ",")
		} else {
			parts = strings.Fields(str)
		}
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				result = append(result, trimmed)
			}
		}
		*s = result
		return nil
	case yaml.SequenceNode:
		var arr []string
		if err := value.Decode(&arr); err != nil {
			return fmt.Errorf("decoding allowed-tools array: %w", err)
		}
		*s = arr
		return nil
	case yaml.DocumentNode, yaml.MappingNode, yaml.AliasNode:
		return fmt.Errorf("allowed-tools: expected string or array, got unsupported YAML node type")
	}
	return fmt.Errorf("allowed-tools: unexpected YAML node kind %d", value.Kind)
}

// skillDirContent holds the raw files and parsed metadata from a skill directory.
type skillDirContent struct {
	skillMD []byte
	// files maps relative paths (e.g., "scripts/run.sh") to content.
	files map[string][]byte
	// fm is the parsed frontmatter.
	fm *frontmatter
}

// maxFrontmatterSize limits frontmatter to prevent YAML parsing attacks.
const maxFrontmatterSize = 64 * 1024

// Compile-time assertion that Packager implements SkillPackager.
var _ SkillPackager = (*Packager)(nil)

// NewPackager creates a new packager with the given store.
// Panics if store is nil.
func NewPackager(store *Store) *Packager {
	if store == nil {
		panic("skills: NewPackager called with nil store")
	}
	return &Packager{store: store}
}

// DefaultPackageOptions returns default packaging options.
// Respects SOURCE_DATE_EPOCH for reproducible builds.
func DefaultPackageOptions() PackageOptions {
	epoch := time.Unix(0, 0).UTC()

	if sde := os.Getenv("SOURCE_DATE_EPOCH"); sde != "" {
		if ts, err := strconv.ParseInt(sde, 10, 64); err == nil {
			epoch = time.Unix(ts, 0).UTC()
		}
	}

	return PackageOptions{
		Epoch:     epoch,
		Platforms: DefaultPlatforms,
	}
}

// Package packages a skill directory into an OCI artifact in the local store.
func (p *Packager) Package(ctx context.Context, skillDir string, opts PackageOptions) (*PackageResult, error) {
	if len(opts.Platforms) == 0 {
		opts.Platforms = DefaultPlatforms
	}

	// Read and validate skill directory
	content, err := readSkillDirectory(skillDir)
	if err != nil {
		return nil, fmt.Errorf("reading skill directory: %w", err)
	}

	// Create content layer (tar.gz) — shared across all platforms
	layerBytes, uncompressedTar, err := createContentLayer(content, opts)
	if err != nil {
		return nil, fmt.Errorf("creating content layer: %w", err)
	}

	layerDigest, err := p.store.PutBlob(ctx, layerBytes)
	if err != nil {
		return nil, fmt.Errorf("storing layer blob: %w", err)
	}

	// Create per-platform config and manifest
	platformManifests := make(map[string]manifestInfo, len(opts.Platforms))
	var primaryManifestDigest, primaryConfigDigest digest.Digest
	var skillConfig *SkillConfig
	var manifestAnnotations map[string]string

	for i, platform := range opts.Platforms {
		platformStr := platform.String()

		ociConfig, cfg := createOCIConfig(content, uncompressedTar, platform, opts)
		configBytes, err := json.Marshal(ociConfig)
		if err != nil {
			return nil, fmt.Errorf("marshaling config for platform %s: %w", platformStr, err)
		}

		configDigest, err := p.store.PutBlob(ctx, configBytes)
		if err != nil {
			return nil, fmt.Errorf("storing config blob for platform %s: %w", platformStr, err)
		}

		manifest := createManifest(configBytes, configDigest, layerBytes, layerDigest, content.fm, opts)
		manifestBytes, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("marshaling manifest for platform %s: %w", platformStr, err)
		}

		manifestDigest, err := p.store.PutManifest(ctx, manifestBytes)
		if err != nil {
			return nil, fmt.Errorf("storing manifest for platform %s: %w", platformStr, err)
		}

		platformManifests[platformStr] = manifestInfo{
			digest: manifestDigest,
			size:   int64(len(manifestBytes)),
		}

		if i == 0 {
			primaryManifestDigest = manifestDigest
			primaryConfigDigest = configDigest
			skillConfig = cfg
			manifestAnnotations = manifest.Annotations
		}
	}

	indexDigest, err := p.createIndex(ctx, platformManifests, manifestAnnotations, opts)
	if err != nil {
		return nil, fmt.Errorf("creating index: %w", err)
	}

	return &PackageResult{
		IndexDigest:    indexDigest,
		ManifestDigest: primaryManifestDigest,
		ConfigDigest:   primaryConfigDigest,
		LayerDigest:    layerDigest,
		Config:         skillConfig,
		Platforms:      opts.Platforms,
	}, nil
}

// readSkillDirectory reads a skill directory, validates its contents, and parses the SKILL.md frontmatter.
func readSkillDirectory(dir string) (*skillDirContent, error) {
	if err := validateSkillDir(dir); err != nil {
		return nil, err
	}

	// Read SKILL.md (required)
	skillMDPath := filepath.Join(dir, "SKILL.md")
	skillMD, err := os.ReadFile(skillMDPath) //#nosec G304 -- path constructed from user-provided skill directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("SKILL.md not found in skill directory")
		}
		return nil, fmt.Errorf("reading SKILL.md: %w", err)
	}

	fm, err := parseFrontmatter(skillMD)
	if err != nil {
		return nil, fmt.Errorf("parsing SKILL.md: %w", err)
	}

	if fm.Name == "" {
		return nil, fmt.Errorf("skill name is required in SKILL.md frontmatter")
	}

	files, err := collectSkillFiles(dir)
	if err != nil {
		return nil, err
	}

	return &skillDirContent{
		skillMD: skillMD,
		files:   files,
		fm:      fm,
	}, nil
}

// validateSkillDir checks that the directory exists and is safe to read.
func validateSkillDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("skill directory not found: %s", dir)
		}
		return fmt.Errorf("accessing skill directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", dir)
	}

	cleanDir := filepath.Clean(dir)
	if strings.Contains(cleanDir, "..") {
		return fmt.Errorf("invalid path: contains path traversal")
	}

	return nil
}

// collectSkillFiles walks a skill directory and returns all regular files (excluding SKILL.md and hidden files).
func collectSkillFiles(dir string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if path == dir {
			return nil
		}

		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("getting relative path: %w", err)
		}
		relPath = filepath.ToSlash(relPath)

		// Skip hidden files/directories
		if strings.HasPrefix(filepath.Base(relPath), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Security: reject symlinked directories (WalkDir follows them silently)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlinks not allowed in skill directory: %s", relPath)
		}

		if d.IsDir() {
			return nil
		}

		if err := validateSkillFile(path, relPath); err != nil {
			return err
		}

		// Skip SKILL.md since we handle it separately
		if relPath == "SKILL.md" {
			return nil
		}

		content, err := os.ReadFile(path) //#nosec G304 -- path from WalkDir, symlink-checked
		if err != nil {
			return fmt.Errorf("reading %s: %w", relPath, err)
		}

		files[relPath] = content
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking skill directory: %w", err)
	}
	return files, nil
}

// validateSkillFile checks that a file in the skill directory is safe to include.
func validateSkillFile(absPath, relPath string) error {
	fileInfo, err := os.Lstat(absPath)
	if err != nil {
		return fmt.Errorf("checking file type for %s: %w", relPath, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed in skill directory: %s", relPath)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("non-regular file not allowed in skill directory: %s", relPath)
	}
	return nil
}

// parseFrontmatter extracts and parses YAML frontmatter from SKILL.md content.
func parseFrontmatter(content []byte) (*frontmatter, error) {
	content = bytes.TrimSpace(content)

	delimiter := []byte("---")
	if !bytes.HasPrefix(content, delimiter) {
		return nil, fmt.Errorf("SKILL.md must start with YAML frontmatter (---)")
	}

	rest := content[len(delimiter):]
	rest = bytes.TrimPrefix(rest, []byte("\n"))

	endIdx := bytes.Index(rest, delimiter)
	if endIdx == -1 {
		return nil, fmt.Errorf("SKILL.md frontmatter missing closing delimiter (---)")
	}

	fmBytes := rest[:endIdx]

	if len(fmBytes) > maxFrontmatterSize {
		return nil, fmt.Errorf("frontmatter exceeds maximum size of %d bytes", maxFrontmatterSize)
	}

	var fm frontmatter
	if err := yaml.Unmarshal(fmBytes, &fm); err != nil {
		return nil, fmt.Errorf("parsing frontmatter YAML: %w", err)
	}

	return &fm, nil
}

// createContentLayer creates a reproducible tar.gz of the skill content.
// Returns both compressed and uncompressed bytes (uncompressed needed for diff_id).
func createContentLayer(content *skillDirContent, opts PackageOptions) (compressed, uncompressed []byte, err error) {
	var files []FileEntry

	// Add SKILL.md first
	files = append(files, FileEntry{
		Path:    "SKILL.md",
		Content: content.skillMD,
	})

	// Add remaining files sorted by path
	sortedPaths := make([]string, 0, len(content.files))
	for p := range content.files {
		sortedPaths = append(sortedPaths, p)
	}
	slices.Sort(sortedPaths)

	for _, p := range sortedPaths {
		files = append(files, FileEntry{
			Path:    p,
			Content: content.files[p],
		})
	}

	tarOpts := TarOptions{Epoch: opts.Epoch}
	gzipOpts := DefaultGzipOptions()

	uncompressed, err = CreateTar(files, tarOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("creating tar: %w", err)
	}

	compressed, err = Compress(uncompressed, gzipOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("compressing tar: %w", err)
	}

	return compressed, uncompressed, nil
}

// createOCIConfig creates the OCI image config with skill metadata in labels.
func createOCIConfig(
	content *skillDirContent,
	uncompressedTar []byte,
	platform Platform,
	opts PackageOptions,
) (*ocispec.Image, *SkillConfig) {
	// Collect all file paths
	allFiles := []string{"SKILL.md"}
	for p := range content.files {
		allFiles = append(allFiles, p)
	}
	slices.Sort(allFiles)

	skillConfig := &SkillConfig{
		Name:          content.fm.Name,
		Description:   content.fm.Description,
		Version:       content.fm.Version,
		AllowedTools:  content.fm.AllowedTools,
		License:       content.fm.License,
		Compatibility: content.fm.Compatibility,
		Metadata:      content.fm.Metadata,
		Files:         allFiles,
	}

	// Encode arrays as JSON for labels
	allowedToolsJSON, _ := json.Marshal(skillConfig.AllowedTools)
	filesJSON, _ := json.Marshal(skillConfig.Files)

	epoch := opts.Epoch
	ociConfig := &ocispec.Image{
		Created: &epoch,
		Platform: ocispec.Platform{
			Architecture: platform.Architecture,
			OS:           platform.OS,
		},
		Config: ocispec.ImageConfig{
			Labels: map[string]string{
				LabelSkillName:         skillConfig.Name,
				LabelSkillDescription:  skillConfig.Description,
				LabelSkillVersion:      skillConfig.Version,
				LabelSkillAllowedTools: string(allowedToolsJSON),
				LabelSkillLicense:      skillConfig.License,
				LabelSkillFiles:        string(filesJSON),
			},
		},
		RootFS: ocispec.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{digest.FromBytes(uncompressedTar)},
		},
		History: []ocispec.History{
			{
				Created:   &epoch,
				CreatedBy: "toolhive package",
			},
		},
	}

	return ociConfig, skillConfig
}

// createManifest creates the OCI manifest.
func createManifest(
	configBytes []byte,
	configDigest digest.Digest,
	layerBytes []byte,
	layerDigest digest.Digest,
	fm *frontmatter,
	opts PackageOptions,
) *ocispec.Manifest {
	annotations := map[string]string{
		ocispec.AnnotationCreated:  opts.Epoch.Format(time.RFC3339),
		AnnotationSkillName:        fm.Name,
		AnnotationSkillDescription: fm.Description,
		AnnotationSkillVersion:     fm.Version,
	}

	// Add requires annotation if present in metadata
	if reqStr, ok := fm.Metadata["toolhive.requires"]; ok && reqStr != "" {
		lines := strings.Split(reqStr, "\n")
		refs := make([]string, 0, len(lines))
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				refs = append(refs, line)
			}
		}
		if len(refs) > 0 {
			requiresJSON, err := json.Marshal(refs)
			if err == nil {
				annotations[AnnotationSkillRequires] = string(requiresJSON)
			}
		}
	}

	return &ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypeSkill,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(configBytes)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      int64(len(layerBytes)),
			},
		},
		Annotations: annotations,
	}
}

// createIndex creates an OCI image index with per-platform manifests.
func (p *Packager) createIndex(
	ctx context.Context,
	platformManifests map[string]manifestInfo,
	annotations map[string]string,
	opts PackageOptions,
) (digest.Digest, error) {
	manifests := make([]ocispec.Descriptor, 0, len(opts.Platforms))
	for _, platform := range opts.Platforms {
		platformStr := platform.String()
		info, ok := platformManifests[platformStr]
		if !ok {
			return "", fmt.Errorf("missing manifest for platform %s", platformStr)
		}

		manifests = append(manifests, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    info.digest,
			Size:      info.size,
			Platform: &ocispec.Platform{
				Architecture: platform.Architecture,
				OS:           platform.OS,
			},
		})
	}

	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: ArtifactTypeSkill,
		Manifests:    manifests,
		Annotations:  annotations,
	}

	indexBytes, err := json.Marshal(index)
	if err != nil {
		return "", fmt.Errorf("marshaling index: %w", err)
	}

	indexDigest, err := p.store.PutManifest(ctx, indexBytes)
	if err != nil {
		return "", fmt.Errorf("storing index: %w", err)
	}

	return indexDigest, nil
}

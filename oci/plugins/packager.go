// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

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

	"github.com/stacklok/toolhive-core/oci/artifact"
)

const (
	// ManifestFileName is the required manifest file name for a plugin directory.
	ManifestFileName = ".claude-plugin/plugin.json"

	// maxManifestSize limits plugin.json to prevent JSON parsing attacks.
	maxManifestSize = 64 * 1024

	// maxPluginFiles limits the number of files in a plugin directory to prevent
	// memory exhaustion during packaging.
	maxPluginFiles = 1_000

	// maxPluginTotalSize limits the total aggregate size of all files in a plugin
	// directory to prevent memory exhaustion during packaging (100 MB).
	maxPluginTotalSize int64 = 100 * 1024 * 1024

	pluginLayerAnnotation = "plugin.tar.gz"
)

// Packager creates reproducible OCI artifacts from plugin directories.
type Packager struct {
	store *Store
}

// manifestInfo holds a manifest digest along with its size.
type manifestInfo struct {
	digest digest.Digest
	size   int64
}

// pluginManifest represents fields ToolHive reads from .claude-plugin/plugin.json.
type pluginManifest struct {
	Name         string          `json:"name"`
	Description  string          `json:"description"`
	Version      string          `json:"version,omitempty"`
	License      string          `json:"license,omitempty"`
	Commands     json.RawMessage `json:"commands,omitempty"`
	Agents       json.RawMessage `json:"agents,omitempty"`
	Skills       json.RawMessage `json:"skills,omitempty"`
	Hooks        json.RawMessage `json:"hooks,omitempty"`
	MCPServers   json.RawMessage `json:"mcpServers,omitempty"`
	LSPServers   json.RawMessage `json:"lspServers,omitempty"`
	Dependencies json.RawMessage `json:"dependencies,omitempty"`
	Requires     json.RawMessage `json:"requires,omitempty"`
}

// pluginDirContent holds the raw files and parsed metadata from a plugin directory.
type pluginDirContent struct {
	manifest []byte
	// files maps relative paths (e.g., "commands/foo.md") to content.
	files map[string][]byte
	// pm is the parsed manifest.
	pm *pluginManifest
}

// Compile-time assertion that Packager implements PluginPackager.
var _ PluginPackager = (*Packager)(nil)

// NewPackager creates a new packager with the given store.
// Panics if store is nil.
func NewPackager(store *Store) *Packager {
	if store == nil {
		panic("plugins: NewPackager called with nil store")
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
		Platforms: artifact.DefaultPlatforms,
	}
}

// Package packages a plugin directory into an OCI artifact in the local store.
func (p *Packager) Package(ctx context.Context, pluginDir string, opts PackageOptions) (*PackageResult, error) {
	if len(opts.Platforms) == 0 {
		opts.Platforms = artifact.DefaultPlatforms
	}

	content, err := readPluginDirectory(pluginDir)
	if err != nil {
		return nil, fmt.Errorf("reading plugin directory: %w", err)
	}

	layerBytes, uncompressedTar, err := createContentLayer(content, opts)
	if err != nil {
		return nil, fmt.Errorf("creating content layer: %w", err)
	}

	layerDigest, err := p.store.PutBlob(ctx, layerBytes)
	if err != nil {
		return nil, fmt.Errorf("storing layer blob: %w", err)
	}

	platformManifests := make(map[string]manifestInfo, len(opts.Platforms))
	var primaryManifestDigest, primaryConfigDigest digest.Digest
	var pluginConfig *PluginConfig
	var manifestAnnotations map[string]string

	for i, platform := range opts.Platforms {
		platformStr := artifact.PlatformString(platform)

		ociConfig, cfg := createOCIConfig(content, uncompressedTar, platform, opts)
		configBytes, err := json.Marshal(ociConfig)
		if err != nil {
			return nil, fmt.Errorf("marshaling config for platform %s: %w", platformStr, err)
		}

		configDigest, err := p.store.PutBlob(ctx, configBytes)
		if err != nil {
			return nil, fmt.Errorf("storing config blob for platform %s: %w", platformStr, err)
		}

		manifest := createManifest(configBytes, configDigest, layerBytes, layerDigest, cfg, opts)
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
			pluginConfig = cfg
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
		Config:         pluginConfig,
		Platforms:      opts.Platforms,
	}, nil
}

// readPluginDirectory reads a plugin directory, validates its contents, and parses the manifest.
func readPluginDirectory(dir string) (*pluginDirContent, error) {
	if err := validatePluginDir(dir); err != nil {
		return nil, err
	}

	manifestPath := filepath.Join(dir, ManifestFileName)
	manifest, err := os.ReadFile(manifestPath) //#nosec G304 -- path constructed from user-provided plugin directory
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found in plugin directory: %w", ManifestFileName, ErrPluginManifestMissing)
		}
		return nil, fmt.Errorf("reading %s: %w", ManifestFileName, err)
	}

	pm, err := parseManifest(manifest)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", ManifestFileName, err)
	}

	if pm.Name == "" {
		return nil, fmt.Errorf("plugin name is required in %s: %w", ManifestFileName, ErrInvalidPluginManifest)
	}

	files, err := collectPluginFiles(dir)
	if err != nil {
		return nil, err
	}

	return &pluginDirContent{
		manifest: manifest,
		files:    files,
		pm:       pm,
	}, nil
}

// validatePluginDir checks that the directory exists and is safe to read.
func validatePluginDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("plugin directory not found: %s: %w", dir, ErrInvalidPluginDir)
		}
		return fmt.Errorf("accessing plugin directory: %w: %w", err, ErrInvalidPluginDir)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s: %w", dir, ErrInvalidPluginDir)
	}

	cleanDir := filepath.Clean(dir)
	if strings.Contains(cleanDir, "..") {
		return fmt.Errorf("invalid path: contains path traversal: %w", ErrInvalidPluginDir)
	}

	return nil
}

// collectPluginFiles walks a plugin directory and returns all regular files
// (excluding hidden files except .claude-plugin/plugin.json). It enforces limits
// on file count and total aggregate size to prevent memory exhaustion.
func collectPluginFiles(dir string) (map[string][]byte, error) {
	files := make(map[string][]byte)
	var totalSize int64
	if err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir {
			return nil
		}
		return collectPluginFile(dir, path, d, files, &totalSize)
	}); err != nil {
		return nil, fmt.Errorf("walking plugin directory: %w", err)
	}
	return files, nil
}

func collectPluginFile(dir, path string, d fs.DirEntry, files map[string][]byte, totalSize *int64) error {
	relPath, err := filepath.Rel(dir, path)
	if err != nil {
		return fmt.Errorf("getting relative path: %w", err)
	}
	relPath = filepath.ToSlash(relPath)

	if d.Type()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed in plugin directory: %s: %w", relPath, ErrInvalidPluginFile)
	}

	if d.IsDir() {
		if strings.HasPrefix(filepath.Base(relPath), ".") && relPath != ".claude-plugin" {
			return filepath.SkipDir
		}
		return nil
	}

	if err := validatePluginFile(path, relPath); err != nil {
		return err
	}

	if isHiddenPath(relPath) && !isAllowedHiddenPluginFile(relPath) {
		return nil
	}

	if relPath == ManifestFileName {
		return nil
	}

	if len(files) >= maxPluginFiles {
		return fmt.Errorf("plugin directory exceeds maximum of %d files: %w", maxPluginFiles, ErrTooManyFiles)
	}

	content, err := os.ReadFile(path) //#nosec G304,G122 -- path from WalkDir, symlink-checked
	if err != nil {
		return fmt.Errorf("reading %s: %w", relPath, err)
	}

	*totalSize += int64(len(content))
	if *totalSize > maxPluginTotalSize {
		return fmt.Errorf("plugin directory exceeds maximum total size of %d bytes: %w", maxPluginTotalSize, ErrPluginTooLarge)
	}

	files[relPath] = content
	return nil
}

// validatePluginFile checks that a file in the plugin directory is safe to include.
func validatePluginFile(absPath, relPath string) error {
	fileInfo, err := os.Lstat(absPath)
	if err != nil {
		return fmt.Errorf("checking file type for %s: %w", relPath, err)
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks not allowed in plugin directory: %s: %w", relPath, ErrInvalidPluginFile)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("non-regular file not allowed in plugin directory: %s: %w", relPath, ErrInvalidPluginFile)
	}
	return nil
}

func isHiddenPath(relPath string) bool {
	parts := strings.Split(relPath, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ".") {
			return true
		}
	}
	return false
}

func isAllowedHiddenPluginFile(relPath string) bool {
	return relPath == ".mcp.json" || relPath == ManifestFileName
}

// parseManifest parses .claude-plugin/plugin.json content.
func parseManifest(content []byte) (*pluginManifest, error) {
	content = bytes.TrimSpace(content)
	if len(content) > maxManifestSize {
		return nil, fmt.Errorf("manifest exceeds maximum size of %d bytes: %w", maxManifestSize, ErrInvalidPluginManifest)
	}

	var pm pluginManifest
	if err := json.Unmarshal(content, &pm); err != nil {
		return nil, fmt.Errorf("parsing manifest JSON: %w: %w", err, ErrInvalidPluginManifest)
	}

	return &pm, nil
}

// createContentLayer creates a reproducible tar.gz of the plugin content.
// Returns both compressed and uncompressed bytes (uncompressed needed for diff_id).
func createContentLayer(content *pluginDirContent, opts PackageOptions) (compressed, uncompressed []byte, err error) {
	var files []artifact.FileEntry

	files = append(files, artifact.FileEntry{
		Path:    ManifestFileName,
		Content: content.manifest,
	})

	sortedPaths := make([]string, 0, len(content.files))
	for p := range content.files {
		sortedPaths = append(sortedPaths, p)
	}
	slices.Sort(sortedPaths)

	for _, p := range sortedPaths {
		files = append(files, artifact.FileEntry{
			Path:    p,
			Content: content.files[p],
		})
	}

	tarOpts := artifact.TarOptions{Epoch: opts.Epoch}
	gzipOpts := artifact.DefaultGzipOptions()

	uncompressed, err = artifact.CreateTar(files, tarOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("creating tar: %w", err)
	}

	compressed, err = artifact.Compress(uncompressed, gzipOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("compressing tar: %w", err)
	}

	return compressed, uncompressed, nil
}

// createOCIConfig creates the OCI image config with plugin metadata in labels.
func createOCIConfig(
	content *pluginDirContent,
	uncompressedTar []byte,
	platform ocispec.Platform,
	opts PackageOptions,
) (*ocispec.Image, *PluginConfig) {
	cfg := pluginConfig(content)

	filesJSON, _ := json.Marshal(cfg.Files)
	componentsJSON, _ := json.Marshal(cfg.Components)
	requiresJSON, _ := json.Marshal(cfg.Requires)

	epoch := opts.Epoch
	ociConfig := &ocispec.Image{
		Created:  &epoch,
		Platform: platform,
		Config: ocispec.ImageConfig{
			Labels: map[string]string{
				LabelPluginName:        cfg.Name,
				LabelPluginDescription: cfg.Description,
				LabelPluginVersion:     cfg.Version,
				LabelPluginLicense:     cfg.License,
				LabelPluginFiles:       string(filesJSON),
				LabelPluginComponents:  string(componentsJSON),
				LabelPluginRequires:    string(requiresJSON),
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

	return ociConfig, cfg
}

func pluginConfig(content *pluginDirContent) *PluginConfig {
	allFiles := []string{ManifestFileName}
	for p := range content.files {
		allFiles = append(allFiles, p)
	}
	slices.Sort(allFiles)

	return &PluginConfig{
		Name:        content.pm.Name,
		Description: content.pm.Description,
		Version:     content.pm.Version,
		License:     content.pm.License,
		Files:       allFiles,
		Components:  componentInventory(content.pm),
		Requires:    requires(content.pm),
	}
}

func componentInventory(pm *pluginManifest) ComponentInventory {
	components := ComponentInventory{}
	addCount := func(name string, raw json.RawMessage) {
		if len(bytes.TrimSpace(raw)) == 0 {
			return
		}
		if count := jsonComponentCount(raw); count > 0 {
			components[name] = count
		}
	}

	addCount("commands", pm.Commands)
	addCount("agents", pm.Agents)
	addCount("skills", pm.Skills)
	addCount("hooks", pm.Hooks)
	addCount("mcpServers", pm.MCPServers)
	addCount("lspServers", pm.LSPServers)

	// Return nil rather than an empty map so the value round-trips cleanly:
	// an empty map is dropped by the `omitempty` config/annotation tags and
	// reparsed as nil, so a zero-component plugin must produce nil here too.
	if len(components) == 0 {
		return nil
	}

	return components
}

func jsonComponentCount(raw json.RawMessage) int {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		return len(arr)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		return len(obj)
	}

	return 1
}

func requires(pm *pluginManifest) []string {
	refs := stringArray(pm.Requires)
	refs = append(refs, stringArray(pm.Dependencies)...)
	slices.Sort(refs)
	return slices.Compact(refs)
}

func stringArray(raw json.RawMessage) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}

	var refs []string
	if err := json.Unmarshal(raw, &refs); err == nil {
		return refs
	}

	var obj map[string]string
	if err := json.Unmarshal(raw, &obj); err == nil {
		refs := make([]string, 0, len(obj))
		for _, ref := range obj {
			if ref != "" {
				refs = append(refs, ref)
			}
		}
		return refs
	}

	return nil
}

// createManifest creates the OCI manifest.
func createManifest(
	configBytes []byte,
	configDigest digest.Digest,
	layerBytes []byte,
	layerDigest digest.Digest,
	cfg *PluginConfig,
	opts PackageOptions,
) *ocispec.Manifest {
	filesJSON, _ := json.Marshal(cfg.Files)
	componentsJSON, _ := json.Marshal(cfg.Components)
	requiresJSON, _ := json.Marshal(cfg.Requires)

	annotations := map[string]string{
		ocispec.AnnotationCreated:     opts.Epoch.Format(time.RFC3339),
		AnnotationPluginName:          cfg.Name,
		AnnotationPluginDescription:   cfg.Description,
		AnnotationPluginVersion:       cfg.Version,
		AnnotationPluginLicense:       cfg.License,
		AnnotationPluginFiles:         string(filesJSON),
		AnnotationPluginComponents:    string(componentsJSON),
		AnnotationPluginRequires:      string(requiresJSON),
		ocispec.AnnotationVersion:     cfg.Version,
		ocispec.AnnotationLicenses:    cfg.License,
		ocispec.AnnotationTitle:       cfg.Name,
		ocispec.AnnotationDescription: cfg.Description,
	}

	return &ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: ArtifactTypePlugin,
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
				Annotations: map[string]string{
					ocispec.AnnotationTitle: pluginLayerAnnotation,
				},
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
		platformStr := artifact.PlatformString(platform)
		info, ok := platformManifests[platformStr]
		if !ok {
			return "", fmt.Errorf("missing manifest for platform %s", platformStr)
		}

		p := platform // copy for pointer
		manifests = append(manifests, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    info.digest,
			Size:      info.size,
			Platform:  &p,
		})
	}

	index := ocispec.Index{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageIndex,
		ArtifactType: ArtifactTypePlugin,
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

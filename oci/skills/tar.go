// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// TarOptions configures reproducible tar archive creation.
type TarOptions struct {
	// Epoch is the timestamp to use for all files (defaults to Unix epoch).
	Epoch time.Time
}

// DefaultTarOptions returns default options for reproducible tar archives.
func DefaultTarOptions() TarOptions {
	return TarOptions{
		Epoch: time.Unix(0, 0).UTC(),
	}
}

// FileEntry represents a file to include in a tar archive.
type FileEntry struct {
	Path    string // Path within the archive
	Content []byte // File content
	Mode    int64  // File mode (defaults to 0644)
}

// CreateTar creates a reproducible tar archive from the given files.
// Files are sorted alphabetically and normalized headers are used
// to ensure deterministic output.
func CreateTar(files []FileEntry, opts TarOptions) ([]byte, error) {
	if opts.Epoch.IsZero() {
		opts.Epoch = time.Unix(0, 0).UTC()
	}

	// Sort files for deterministic ordering
	sorted := make([]FileEntry, len(files))
	copy(sorted, files)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, f := range sorted {
		mode := f.Mode
		if mode == 0 {
			mode = 0644
		}

		hdr := &tar.Header{
			Name:     f.Path,
			Size:     int64(len(f.Content)),
			Mode:     mode,
			ModTime:  opts.Epoch,
			Uid:      0,
			Gid:      0,
			Uname:    "",
			Gname:    "",
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("writing tar header for %s: %w", f.Path, err)
		}

		if _, err := tw.Write(f.Content); err != nil {
			return nil, fmt.Errorf("writing tar content for %s: %w", f.Path, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("closing tar writer: %w", err)
	}

	return buf.Bytes(), nil
}

// MaxTarFileSize is the maximum size of a single file in a tar archive (100MB).
// This prevents decompression bombs.
const MaxTarFileSize = 100 * 1024 * 1024

// ExtractTar extracts files from a tar archive.
func ExtractTar(data []byte) ([]FileEntry, error) {
	return ExtractTarWithLimit(data, MaxTarFileSize)
}

// ExtractTarWithLimit extracts files from a tar archive with a per-file size limit.
// It rejects symlinks, hardlinks, device entries, and paths containing traversal sequences.
func ExtractTarWithLimit(data []byte, maxFileSize int64) ([]FileEntry, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var files []FileEntry

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar header: %w", err)
		}

		// Reject path traversal
		if err := validateTarPath(hdr.Name); err != nil {
			return nil, err
		}

		// Skip directories
		if hdr.Typeflag == tar.TypeDir {
			continue
		}

		// Reject symlinks and hardlinks
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return nil, fmt.Errorf("archive contains disallowed link type: %s", hdr.Name)
		}

		// Reject device entries and other special types
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("archive contains disallowed entry type %d: %s", hdr.Typeflag, hdr.Name)
		}

		// Check declared size against limit
		if hdr.Size > maxFileSize {
			return nil, fmt.Errorf("file %s exceeds maximum size of %d bytes", hdr.Name, maxFileSize)
		}

		// Use LimitReader to enforce the limit during reading
		limitedReader := io.LimitReader(tr, maxFileSize+1)
		content, err := io.ReadAll(limitedReader)
		if err != nil {
			return nil, fmt.Errorf("reading tar content for %s: %w", hdr.Name, err)
		}

		if int64(len(content)) > maxFileSize {
			return nil, fmt.Errorf("file %s exceeds maximum size of %d bytes", hdr.Name, maxFileSize)
		}

		files = append(files, FileEntry{
			Path:    hdr.Name,
			Content: content,
			Mode:    hdr.Mode,
		})
	}

	return files, nil
}

// validateTarPath checks that a tar entry path is safe.
func validateTarPath(p string) error {
	// path.Clean resolves all ".." segments; any remaining leading ".."
	// means the path escapes the archive root.
	cleaned := path.Clean(p)
	if strings.HasPrefix(cleaned, "..") {
		return fmt.Errorf("path traversal detected in archive: %s", p)
	}
	if path.IsAbs(cleaned) {
		return fmt.Errorf("absolute path not allowed in archive: %s", p)
	}
	return nil
}

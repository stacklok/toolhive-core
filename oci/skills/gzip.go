// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"time"
)

// gzipOSUnknown is the OS value for "unknown" in gzip headers (RFC 1952).
// Using this value ensures cross-platform reproducibility.
const gzipOSUnknown = 255

// GzipOptions configures reproducible gzip compression.
type GzipOptions struct {
	// Level is the compression level (defaults to gzip.BestCompression).
	Level int

	// Epoch is the modification time to use in the gzip header.
	// If zero, uses Unix epoch (1970-01-01) for reproducibility.
	Epoch time.Time
}

// DefaultGzipOptions returns default options for reproducible gzip compression.
func DefaultGzipOptions() GzipOptions {
	return GzipOptions{
		Level: gzip.BestCompression,
		Epoch: time.Unix(0, 0).UTC(),
	}
}

// Compress creates a reproducible gzip compressed byte slice.
// Headers are explicitly controlled for reproducibility:
// - ModTime: uses opts.Epoch (defaults to Unix epoch)
// - Name: empty (no filename)
// - Comment: empty
// - OS: 255 (unknown) for cross-platform consistency
func Compress(data []byte, opts GzipOptions) ([]byte, error) {
	if opts.Level == 0 {
		opts.Level = gzip.BestCompression
	}

	// Use Unix epoch if no epoch specified
	epoch := opts.Epoch
	if epoch.IsZero() {
		epoch = time.Unix(0, 0).UTC()
	}

	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, opts.Level)
	if err != nil {
		return nil, fmt.Errorf("creating gzip writer: %w", err)
	}

	// Explicitly set header fields for reproducibility
	gw.ModTime = epoch
	gw.Name = ""
	gw.Comment = ""
	gw.OS = gzipOSUnknown

	if _, err := gw.Write(data); err != nil {
		return nil, fmt.Errorf("writing gzip data: %w", err)
	}

	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("closing gzip writer: %w", err)
	}

	return buf.Bytes(), nil
}

// MaxDecompressedSize is the maximum size of decompressed data (100MB).
// This prevents decompression bombs.
const MaxDecompressedSize = 100 * 1024 * 1024

// Decompress decompresses gzip data.
func Decompress(data []byte) ([]byte, error) {
	return DecompressWithLimit(data, MaxDecompressedSize)
}

// DecompressWithLimit decompresses gzip data with a size limit.
func DecompressWithLimit(data []byte, maxSize int64) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// Limit read size to prevent decompression bombs
	limitedReader := io.LimitReader(gr, maxSize+1)
	result, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("reading gzip data: %w", err)
	}

	if int64(len(result)) > maxSize {
		return nil, fmt.Errorf("decompressed data exceeds maximum size of %d bytes", maxSize)
	}

	return result, nil
}

// CompressTar creates a reproducible .tar.gz from the given files.
func CompressTar(files []FileEntry, tarOpts TarOptions, gzipOpts GzipOptions) ([]byte, error) {
	tarData, err := CreateTar(files, tarOpts)
	if err != nil {
		return nil, fmt.Errorf("creating tar: %w", err)
	}

	gzipData, err := Compress(tarData, gzipOpts)
	if err != nil {
		return nil, fmt.Errorf("compressing tar: %w", err)
	}

	return gzipData, nil
}

// DecompressTar extracts files from a .tar.gz archive.
func DecompressTar(data []byte) ([]FileEntry, error) {
	tarData, err := Decompress(data)
	if err != nil {
		return nil, fmt.Errorf("decompressing gzip: %w", err)
	}

	files, err := ExtractTar(tarData)
	if err != nil {
		return nil, fmt.Errorf("extracting tar: %w", err)
	}

	return files, nil
}

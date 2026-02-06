// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompress_Reproducible(t *testing.T) {
	t.Parallel()

	data := []byte("test data for compression")
	opts := DefaultGzipOptions()

	gz1, err := Compress(data, opts)
	require.NoError(t, err)

	gz2, err := Compress(data, opts)
	require.NoError(t, err)

	assert.Equal(t, gz1, gz2, "Compress should produce identical output for same input")
}

func TestCompress_HeaderFieldsForReproducibility(t *testing.T) {
	t.Parallel()

	data := []byte("test data")
	epoch := time.Unix(1234567890, 0).UTC()
	opts := GzipOptions{
		Level: gzip.BestCompression,
		Epoch: epoch,
	}

	compressed, err := Compress(data, opts)
	require.NoError(t, err)

	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	defer gr.Close()

	assert.True(t, gr.ModTime.Equal(epoch), "ModTime should match epoch")
	assert.Empty(t, gr.Name, "Name should be empty")
	assert.Empty(t, gr.Comment, "Comment should be empty")
	assert.Equal(t, byte(gzipOSUnknown), gr.OS, "OS should be 255 (unknown)")
}

func TestCompress_DifferentEpochs(t *testing.T) {
	t.Parallel()

	data := []byte("test data")

	tests := []struct {
		name      string
		epoch1    time.Time
		epoch2    time.Time
		wantEqual bool
	}{
		{
			name:      "same epoch produces same output",
			epoch1:    time.Unix(1609459200, 0).UTC(),
			epoch2:    time.Unix(1609459200, 0).UTC(),
			wantEqual: true,
		},
		{
			name:      "different epochs produce different output",
			epoch1:    time.Unix(0, 0).UTC(),
			epoch2:    time.Unix(1000000, 0).UTC(),
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			opts1 := GzipOptions{Level: gzip.BestCompression, Epoch: tt.epoch1}
			opts2 := GzipOptions{Level: gzip.BestCompression, Epoch: tt.epoch2}

			gz1, err := Compress(data, opts1)
			require.NoError(t, err)

			gz2, err := Compress(data, opts2)
			require.NoError(t, err)

			if tt.wantEqual {
				assert.Equal(t, gz1, gz2)
			} else {
				assert.NotEqual(t, gz1, gz2)
			}
		})
	}
}

func TestCompress_SameEpochAlwaysReproducible(t *testing.T) {
	t.Parallel()

	data := []byte("test data for reproducibility check")
	epoch := time.Unix(1609459200, 0).UTC()
	opts := GzipOptions{Level: gzip.BestCompression, Epoch: epoch}

	results := make([][]byte, 5)
	for i := range results {
		var err error
		results[i], err = Compress(data, opts)
		require.NoError(t, err)
	}

	for i := 1; i < len(results); i++ {
		assert.Equal(t, results[0], results[i], "iteration %d should match", i)
	}
}

func TestCompressDecompress_RoundTrip(t *testing.T) {
	t.Parallel()

	original := []byte("test data for round trip")
	opts := DefaultGzipOptions()

	compressed, err := Compress(original, opts)
	require.NoError(t, err)

	decompressed, err := Decompress(compressed)
	require.NoError(t, err)

	assert.Equal(t, original, decompressed)
}

func TestDecompressWithLimit_RejectsOversized(t *testing.T) {
	t.Parallel()

	// Create compressed data that exceeds the limit when decompressed
	data := bytes.Repeat([]byte("x"), 1024)
	compressed, err := Compress(data, DefaultGzipOptions())
	require.NoError(t, err)

	_, err = DecompressWithLimit(compressed, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestCompressTar_Reproducible(t *testing.T) {
	t.Parallel()

	files := []FileEntry{
		{Path: "b.txt", Content: []byte("content b")},
		{Path: "a.txt", Content: []byte("content a")},
	}

	tarOpts := DefaultTarOptions()
	gzipOpts := DefaultGzipOptions()

	gz1, err := CompressTar(files, tarOpts, gzipOpts)
	require.NoError(t, err)

	gz2, err := CompressTar(files, tarOpts, gzipOpts)
	require.NoError(t, err)

	assert.Equal(t, gz1, gz2, "CompressTar should produce identical output")
}

func TestCompressTar_RoundTrip(t *testing.T) {
	t.Parallel()

	originalFiles := []FileEntry{
		{Path: "a.txt", Content: []byte("content a")},
		{Path: "dir/b.txt", Content: []byte("content b")},
	}

	tarOpts := DefaultTarOptions()
	gzipOpts := DefaultGzipOptions()

	compressed, err := CompressTar(originalFiles, tarOpts, gzipOpts)
	require.NoError(t, err)

	extractedFiles, err := DecompressTar(compressed)
	require.NoError(t, err)

	require.Len(t, extractedFiles, len(originalFiles))
	for i, f := range extractedFiles {
		assert.Equal(t, originalFiles[i].Path, f.Path)
		assert.Equal(t, originalFiles[i].Content, f.Content)
	}
}

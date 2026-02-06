// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	"archive/tar"
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateTar_Reproducible(t *testing.T) {
	t.Parallel()

	files := []FileEntry{
		{Path: "b.txt", Content: []byte("content b")},
		{Path: "a.txt", Content: []byte("content a")},
		{Path: "c/d.txt", Content: []byte("content d")},
	}

	opts := DefaultTarOptions()

	tar1, err := CreateTar(files, opts)
	require.NoError(t, err)

	tar2, err := CreateTar(files, opts)
	require.NoError(t, err)

	assert.Equal(t, tar1, tar2, "CreateTar should produce identical output for same input")
}

func TestCreateTar_DifferentOrder(t *testing.T) {
	t.Parallel()

	files1 := []FileEntry{
		{Path: "b.txt", Content: []byte("b")},
		{Path: "a.txt", Content: []byte("a")},
	}

	files2 := []FileEntry{
		{Path: "a.txt", Content: []byte("a")},
		{Path: "b.txt", Content: []byte("b")},
	}

	opts := DefaultTarOptions()

	tar1, err := CreateTar(files1, opts)
	require.NoError(t, err)

	tar2, err := CreateTar(files2, opts)
	require.NoError(t, err)

	assert.Equal(t, tar1, tar2, "CreateTar should sort files internally")
}

func TestCreateTar_DifferentTimestamps(t *testing.T) {
	t.Parallel()

	files := []FileEntry{
		{Path: "test.txt", Content: []byte("test")},
	}

	tests := []struct {
		name      string
		opts1     TarOptions
		opts2     TarOptions
		wantEqual bool
	}{
		{
			name:      "same epoch produces same output",
			opts1:     TarOptions{Epoch: time.Unix(0, 0).UTC()},
			opts2:     TarOptions{Epoch: time.Unix(0, 0).UTC()},
			wantEqual: true,
		},
		{
			name:      "different epochs produce different output",
			opts1:     TarOptions{Epoch: time.Unix(0, 0).UTC()},
			opts2:     TarOptions{Epoch: time.Unix(1000000, 0).UTC()},
			wantEqual: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tar1, err := CreateTar(files, tt.opts1)
			require.NoError(t, err)

			tar2, err := CreateTar(files, tt.opts2)
			require.NoError(t, err)

			if tt.wantEqual {
				assert.Equal(t, tar1, tar2)
			} else {
				assert.NotEqual(t, tar1, tar2)
			}
		})
	}
}

func TestExtractTar_RoundTrip(t *testing.T) {
	t.Parallel()

	originalFiles := []FileEntry{
		{Path: "a.txt", Content: []byte("content a")},
		{Path: "b/c.txt", Content: []byte("content c")},
	}

	tarData, err := CreateTar(originalFiles, DefaultTarOptions())
	require.NoError(t, err)

	extractedFiles, err := ExtractTar(tarData)
	require.NoError(t, err)

	require.Len(t, extractedFiles, len(originalFiles))

	for i, f := range extractedFiles {
		assert.Equal(t, originalFiles[i].Path, f.Path)
		assert.Equal(t, originalFiles[i].Content, f.Content)
	}
}

func TestCreateTar_EmptyFiles(t *testing.T) {
	t.Parallel()

	tarData, err := CreateTar(nil, DefaultTarOptions())
	require.NoError(t, err)

	extractedFiles, err := ExtractTar(tarData)
	require.NoError(t, err)

	assert.Empty(t, extractedFiles)
}

func TestExtractTar_RejectsSymlinks(t *testing.T) {
	t.Parallel()

	// Create a tar with a symlink entry
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:     "malicious_link",
		Typeflag: tar.TypeSymlink,
		Linkname: "/etc/passwd",
	}
	require.NoError(t, tw.WriteHeader(hdr))
	require.NoError(t, tw.Close())

	_, err := ExtractTar(buf.Bytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed link type")
}

func TestExtractTar_RejectsHardlinks(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:     "malicious_link",
		Typeflag: tar.TypeLink,
		Linkname: "other_file",
	}
	require.NoError(t, tw.WriteHeader(hdr))
	require.NoError(t, tw.Close())

	_, err := ExtractTar(buf.Bytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed link type")
}

func TestExtractTar_RejectsDeviceEntries(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	hdr := &tar.Header{
		Name:     "malicious_device",
		Typeflag: tar.TypeChar,
		Mode:     0666,
	}
	require.NoError(t, tw.WriteHeader(hdr))
	require.NoError(t, tw.Close())

	_, err := ExtractTar(buf.Bytes())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disallowed entry type")
}

func TestExtractTar_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "dotdot prefix", path: "../etc/passwd"},
		{name: "dotdot in middle", path: "foo/../../etc/passwd"},
		{name: "absolute path", path: "/etc/passwd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)

			hdr := &tar.Header{
				Name:     tt.path,
				Size:     4,
				Typeflag: tar.TypeReg,
				Mode:     0644,
			}
			require.NoError(t, tw.WriteHeader(hdr))
			_, err := tw.Write([]byte("test"))
			require.NoError(t, err)
			require.NoError(t, tw.Close())

			_, err = ExtractTar(buf.Bytes())
			assert.Error(t, err)
		})
	}
}

func TestExtractTarWithLimit_RejectsOversized(t *testing.T) {
	t.Parallel()

	files := []FileEntry{
		{Path: "big.txt", Content: bytes.Repeat([]byte("x"), 1024)},
	}

	tarData, err := CreateTar(files, DefaultTarOptions())
	require.NoError(t, err)

	_, err = ExtractTarWithLimit(tarData, 100)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

func TestExtractTar_SkipsDirectories(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Write a directory entry
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "mydir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	}))

	// Write a file inside it
	content := []byte("hello")
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name:     "mydir/file.txt",
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	}))
	_, err := tw.Write(content)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	files, err := ExtractTar(buf.Bytes())
	require.NoError(t, err)

	require.Len(t, files, 1)
	assert.Equal(t, "mydir/file.txt", files[0].Path)
	assert.Equal(t, content, files[0].Content)
}

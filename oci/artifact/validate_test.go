// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package artifact

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/memory"
)

func TestIsManifestMediaType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mediaType string
		want      bool
	}{
		{name: "oci image manifest", mediaType: ocispec.MediaTypeImageManifest, want: true},
		{name: "oci image index", mediaType: ocispec.MediaTypeImageIndex, want: true},
		{name: "docker manifest v2", mediaType: "application/vnd.docker.distribution.manifest.v2+json", want: true},
		{name: "docker manifest list v2", mediaType: "application/vnd.docker.distribution.manifest.list.v2+json", want: true},
		{name: "oci image layer", mediaType: ocispec.MediaTypeImageLayerGzip, want: false},
		{name: "oci image config", mediaType: ocispec.MediaTypeImageConfig, want: false},
		{name: "empty", mediaType: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isManifestMediaType(tt.mediaType))
		})
	}
}

func TestValidatingTarget_Push(t *testing.T) {
	t.Parallel()

	validManifest := []byte(`{"schemaVersion": 2}`)
	oversized := make([]byte, MaxManifestSize+1)

	tests := []struct {
		name      string
		desc      ocispec.Descriptor
		content   []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name: "accepts valid content",
			desc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromBytes(validManifest),
				Size:      int64(len(validManifest)),
			},
			content: validManifest,
			wantErr: false,
		},
		{
			name: "rejects oversized declared size",
			desc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromBytes(oversized),
				Size:      int64(len(oversized)),
			},
			content:   oversized,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed size",
		},
		{
			name: "rejects lying (too-small) descriptor size",
			desc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromBytes(oversized),
				Size:      10, // lying
			},
			content:   oversized,
			wantErr:   true,
			errSubstr: "exceeds maximum allowed size",
		},
		{
			name: "rejects negative size",
			desc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("test"),
				Size:      -1,
			},
			content:   []byte("test"),
			wantErr:   true,
			errSubstr: "invalid negative content size",
		},
		{
			name: "rejects digest mismatch",
			desc: ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    digest.FromString("something-else"),
				Size:      int64(len(validManifest)),
			},
			content:   validManifest,
			wantErr:   true,
			errSubstr: "digest mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			inner := memory.New()
			vt := NewValidatingTarget(inner)

			err := vt.Push(ctx, tt.desc, bytes.NewReader(tt.content))
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}

			require.NoError(t, err)
			exists, err := inner.Exists(ctx, tt.desc)
			require.NoError(t, err)
			assert.True(t, exists)
		})
	}
}

func TestValidateManifestCounts(t *testing.T) {
	t.Parallel()

	tooManyManifests := func() []byte {
		index := ocispec.Index{MediaType: ocispec.MediaTypeImageIndex}
		index.SchemaVersion = 2
		index.Manifests = make([]ocispec.Descriptor, maxIndexManifests+1)
		data, err := json.Marshal(index)
		require.NoError(t, err)
		return data
	}()

	tooManyLayers := func() []byte {
		m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
		m.Layers = make([]ocispec.Descriptor, maxManifestLayers+1)
		data, err := json.Marshal(m)
		require.NoError(t, err)
		return data
	}()

	validManifest := func() []byte {
		m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest}
		m.Layers = make([]ocispec.Descriptor, 2)
		data, err := json.Marshal(m)
		require.NoError(t, err)
		return data
	}()

	tests := []struct {
		name      string
		mediaType string
		data      []byte
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "too many manifests in index",
			mediaType: ocispec.MediaTypeImageIndex,
			data:      tooManyManifests,
			wantErr:   true,
			errSubstr: "exceeds maximum",
		},
		{
			name:      "too many layers in manifest",
			mediaType: ocispec.MediaTypeImageManifest,
			data:      tooManyLayers,
			wantErr:   true,
			errSubstr: "exceeds maximum",
		},
		{
			name:      "valid counts",
			mediaType: ocispec.MediaTypeImageManifest,
			data:      validManifest,
			wantErr:   false,
		},
		{
			name:      "non-manifest media type is ignored",
			mediaType: ocispec.MediaTypeImageLayerGzip,
			data:      []byte("not json"),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateManifestCounts(tt.mediaType, tt.data)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
		})
	}
}

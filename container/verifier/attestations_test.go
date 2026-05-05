// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"fmt"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

// fakeImage implements v1.Image with a configurable manifest for testing
// isSigstoreBundle. Only Manifest() is used by the code under test; all other
// methods panic if called so that accidental usage is caught immediately.
type fakeImage struct {
	manifest *v1.Manifest
	err      error
}

func (f *fakeImage) Manifest() (*v1.Manifest, error) { return f.manifest, f.err }

// Unused interface methods — panic to surface accidental calls.
func (*fakeImage) Layers() ([]v1.Layer, error)             { panic("not implemented") }
func (*fakeImage) MediaType() (types.MediaType, error)     { panic("not implemented") }
func (*fakeImage) Size() (int64, error)                    { panic("not implemented") }
func (*fakeImage) ConfigName() (v1.Hash, error)            { panic("not implemented") }
func (*fakeImage) ConfigFile() (*v1.ConfigFile, error)     { panic("not implemented") }
func (*fakeImage) RawConfigFile() ([]byte, error)          { panic("not implemented") }
func (*fakeImage) Digest() (v1.Hash, error)                { panic("not implemented") }
func (*fakeImage) RawManifest() ([]byte, error)            { panic("not implemented") }
func (*fakeImage) LayerByDigest(v1.Hash) (v1.Layer, error) { panic("not implemented") }
func (*fakeImage) LayerByDiffID(v1.Hash) (v1.Layer, error) { panic("not implemented") }

func TestHasSigstoreBundlePrefix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "exact v0.1 bundle type",
			input: "application/vnd.dev.sigstore.bundle+json;version=0.1",
			want:  true,
		},
		{
			name:  "v0.3 bundle type",
			input: MediaTypeSigstoreBundleV03JSON,
			want:  true,
		},
		{
			name:  "bare prefix without version",
			input: "application/vnd.dev.sigstore.bundle",
			want:  true,
		},
		{
			name:  "OCI empty type (ambiguous, not a bundle)",
			input: MediaTypeOCIEmptyV1JSON,
			want:  false,
		},
		{
			name:  "cosign simplesigning type",
			input: MediaTypeCosignSimpleSigningV1JSON,
			want:  false,
		},
		{
			name:  "empty string",
			input: "",
			want:  false,
		},
		{
			name:  "unrelated media type",
			input: "application/json",
			want:  false,
		},
		{
			name:  "partial prefix match (missing dev)",
			input: "application/vnd.sigstore.bundle",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := hasSigstoreBundlePrefix(tt.input)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsSigstoreBundle(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		img  v1.Image
		want bool
	}{
		{
			name: "config artifactType is sigstore bundle v0.3",
			img: &fakeImage{manifest: &v1.Manifest{
				Config: v1.Descriptor{
					ArtifactType: MediaTypeSigstoreBundleV03JSON,
				},
			}},
			want: true,
		},
		{
			name: "config artifactType is sigstore bundle v0.1",
			img: &fakeImage{manifest: &v1.Manifest{
				Config: v1.Descriptor{
					ArtifactType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
				},
			}},
			want: true,
		},
		{
			name: "layer media type is sigstore bundle",
			img: &fakeImage{manifest: &v1.Manifest{
				Config: v1.Descriptor{
					ArtifactType: MediaTypeOCIEmptyV1JSON,
				},
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType(MediaTypeSigstoreBundleV03JSON)},
				},
			}},
			want: true,
		},
		{
			name: "neither config nor layers match",
			img: &fakeImage{manifest: &v1.Manifest{
				Config: v1.Descriptor{
					ArtifactType: MediaTypeOCIEmptyV1JSON,
				},
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType("application/vnd.oci.image.layer.v1.tar+gzip")},
				},
			}},
			want: false,
		},
		{
			name: "empty manifest (no config, no layers)",
			img:  &fakeImage{manifest: &v1.Manifest{}},
			want: false,
		},
		{
			name: "manifest fetch error returns false",
			img:  &fakeImage{err: fmt.Errorf("network error")},
			want: false,
		},
		{
			name: "multiple layers, second is sigstore bundle",
			img: &fakeImage{manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType("application/octet-stream")},
					{MediaType: types.MediaType(MediaTypeSigstoreBundleV03JSON)},
				},
			}},
			want: true,
		},
		{
			name: "cosign simplesigning layer is not a sigstore bundle",
			img: &fakeImage{manifest: &v1.Manifest{
				Layers: []v1.Descriptor{
					{MediaType: types.MediaType(MediaTypeCosignSimpleSigningV1JSON)},
				},
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isSigstoreBundle(tt.img)
			require.Equal(t, tt.want, got)
		})
	}
}

// TestBundleFromAttestation_FilterLogic validates the fast-path and
// deep-inspection filtering in bundleFromAttestation by documenting the
// expected skip/inspect behavior for different artifactType values in the
// referrers index. We cannot call bundleFromAttestation directly (it hits the
// network), so instead we verify the two helper predicates that drive the
// filtering logic, mirroring the conditions in the loop:
//
//	skip        = !hasSigstoreBundlePrefix(at) && at != "application/vnd.oci.empty.v1+json" && at != ""
//	deepInspect = !hasSigstoreBundlePrefix(at)   (only reached when not skipped)
func TestBundleFromAttestation_FilterPredicates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		artType  string
		wantSkip bool // true = fast-path skip (no manifest fetch)
		wantDeep bool // true = needs deep inspection via isSigstoreBundle
	}{
		{
			name:     "sigstore bundle v0.3 - accepted without deep inspect",
			artType:  MediaTypeSigstoreBundleV03JSON,
			wantSkip: false,
			wantDeep: false,
		},
		{
			name:     "OCI empty (go-containerregistry bug) - needs deep inspect",
			artType:  MediaTypeOCIEmptyV1JSON,
			wantSkip: false,
			wantDeep: true,
		},
		{
			name:     "empty string - needs deep inspect",
			artType:  "",
			wantSkip: false,
			wantDeep: true,
		},
		{
			name:     "cosign simplesigning - fast-path skip",
			artType:  MediaTypeCosignSimpleSigningV1JSON,
			wantSkip: true,
			wantDeep: false, // never reached
		},
		{
			name:     "arbitrary OCI type - fast-path skip",
			artType:  "application/vnd.oci.image.manifest.v1+json",
			wantSkip: true,
			wantDeep: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Replicate the skip condition from bundleFromAttestation
			skip := !hasSigstoreBundlePrefix(tt.artType) &&
				tt.artType != MediaTypeOCIEmptyV1JSON &&
				tt.artType != ""
			require.Equal(t, tt.wantSkip, skip, "skip predicate mismatch")

			if !skip {
				deepInspect := !hasSigstoreBundlePrefix(tt.artType)
				require.Equal(t, tt.wantDeep, deepInspect, "deep-inspect predicate mismatch")
			}
		})
	}
}

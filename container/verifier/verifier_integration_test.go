// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/require"

	registry "github.com/stacklok/toolhive-core/registry/types"
)

// ocireg-mcp provenance values shared by all versions.
// These match the catalog entry at registries/toolhive/servers/oci-registry/server.json.
var ociregProvenance = &registry.Provenance{
	SigstoreURL:       "tuf-repo-cdn.sigstore.dev",
	RepositoryURI:     "https://github.com/StacklokLabs/ocireg-mcp",
	SignerIdentity:    "/.github/workflows/release.yml",
	RunnerEnvironment: "github-hosted",
	CertIssuer:        "https://token.actions.githubusercontent.com",
}

// TestVerifyServer_LiveImages tests the full VerifyServer flow against real
// public GHCR images. It covers both the legacy cosign .sig tag format and
// the newer OCI 1.1 referrers format (sigstore bundle v0.3).
//
// These tests hit the network (GHCR + sigstore TUF) and are skipped when
// running with -short.
func TestVerifyServer_LiveImages(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping live image verification test (requires network)")
	}

	tests := []struct {
		name       string
		image      string
		provenance *registry.Provenance
		wantErr    error
	}{
		{
			name:       "v0.1.0 - legacy cosign .sig tag signature",
			image:      "ghcr.io/stackloklabs/ocireg-mcp/server:0.1.0",
			provenance: ociregProvenance,
		},
		{
			name:       "v0.2.1 - OCI 1.1 referrers with sigstore bundle v0.3",
			image:      "ghcr.io/stackloklabs/ocireg-mcp/server:0.2.1",
			provenance: ociregProvenance,
		},
		{
			name:  "wrong provenance returns ErrProvenanceMismatch",
			image: "ghcr.io/stackloklabs/ocireg-mcp/server:0.1.0",
			provenance: &registry.Provenance{
				SigstoreURL:       "tuf-repo-cdn.sigstore.dev",
				RepositoryURI:     "https://github.com/wrong/repo",
				SignerIdentity:    "/.github/workflows/release.yml",
				RunnerEnvironment: "github-hosted",
				CertIssuer:        "https://token.actions.githubusercontent.com",
			},
			wantErr: ErrProvenanceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v, err := New(tt.provenance, authn.DefaultKeychain)
			require.NoError(t, err, "failed to create verifier")

			err = v.VerifyServer(tt.image, tt.provenance)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err, "VerifyServer should succeed for %s", tt.image)
			}
		})
	}
}

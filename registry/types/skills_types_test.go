// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	testSkillName       = "commit"
	testSigstoreURL     = "tuf-repo.github.com"
	testRepositoryURI   = "https://github.com/stacklok/dockyard"
	testRepositoryRef   = "refs/heads/main"
	testSignerIdentity  = "/.github/workflows/build-skills.yml"
	testRunnerEnv       = "github-hosted"
	testCertIssuer      = "https://token.actions.githubusercontent.com"
	testSkillIdentifier = "ghcr.io/stacklok/dockyard/skills/commit:1.0.0"

	testCaseFullProvenance = "fully populated provenance"
)

// fullProvenance returns a Provenance with every field populated, matching the
// shape a catalog entry would declare for a skill built by a known workflow.
func fullProvenance() *Provenance {
	return &Provenance{
		SigstoreURL:       testSigstoreURL,
		RepositoryURI:     testRepositoryURI,
		RepositoryRef:     testRepositoryRef,
		SignerIdentity:    testSignerIdentity,
		RunnerEnvironment: testRunnerEnv,
		CertIssuer:        testCertIssuer,
	}
}

// baseSkill returns a minimally valid Skill that individual tests can extend.
func baseSkill() *Skill {
	return &Skill{
		Namespace:   testNamespace,
		Name:        testSkillName,
		Description: testLongDesc,
		Version:     testVersion,
		Status:      testStatusActive,
		Packages: []SkillPackage{
			{
				RegistryType: testRegistryType,
				Identifier:   testSkillIdentifier,
			},
		},
	}
}

// TestSkill_ProvenanceJSONRoundTrip verifies that Skill.Provenance survives a
// JSON round trip intact, and that a nil Provenance is omitted entirely rather
// than serialized as an explicit null.
func TestSkill_ProvenanceJSONRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provenance *Provenance
		// wantKey is whether the "provenance" key should appear in the JSON.
		wantKey bool
	}{
		{
			name:       "provenance unset is omitted",
			provenance: nil,
			wantKey:    false,
		},
		{
			name:       testCaseFullProvenance,
			provenance: fullProvenance(),
			wantKey:    true,
		},
		{
			name: "partially populated provenance",
			provenance: &Provenance{
				SignerIdentity: testSignerIdentity,
				CertIssuer:     testCertIssuer,
			},
			wantKey: true,
		},
		{
			name: "provenance with attestation",
			provenance: &Provenance{
				SignerIdentity: testSignerIdentity,
				Attestation: &VerifiedAttestation{
					PredicateType: "https://slsa.dev/provenance/v1",
					Predicate:     map[string]any{"buildType": "workflow"},
				},
			},
			wantKey: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := baseSkill()
			skill.Provenance = tc.provenance

			data, err := json.Marshal(skill)
			require.NoError(t, err)

			// Assert on the raw shape so omitempty behavior is pinned down,
			// not just the decoded value.
			var raw map[string]any
			require.NoError(t, json.Unmarshal(data, &raw))
			_, hasKey := raw["provenance"]
			assert.Equal(t, tc.wantKey, hasKey, "unexpected presence of provenance key in %s", data)

			var decoded Skill
			require.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, tc.provenance, decoded.Provenance)
			assert.Equal(t, *skill, decoded)
		})
	}
}

// TestSkill_ProvenanceYAMLRoundTrip verifies the same omitempty and round-trip
// behavior for YAML, which the config-style consumers of the catalog use.
func TestSkill_ProvenanceYAMLRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		provenance *Provenance
		wantKey    bool
	}{
		{
			name:       "provenance unset is omitted",
			provenance: nil,
			wantKey:    false,
		},
		{
			name:       testCaseFullProvenance,
			provenance: fullProvenance(),
			wantKey:    true,
		},
		{
			name: "partially populated provenance",
			provenance: &Provenance{
				SignerIdentity: testSignerIdentity,
			},
			wantKey: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := baseSkill()
			skill.Provenance = tc.provenance

			data, err := yaml.Marshal(skill)
			require.NoError(t, err)

			var raw map[string]any
			require.NoError(t, yaml.Unmarshal(data, &raw))
			_, hasKey := raw["provenance"]
			assert.Equal(t, tc.wantKey, hasKey, "unexpected presence of provenance key in %s", data)

			var decoded Skill
			require.NoError(t, yaml.Unmarshal(data, &decoded))
			assert.Equal(t, tc.provenance, decoded.Provenance)
		})
	}
}

// TestSkill_ValidateWithProvenance verifies that Validate accepts skills with
// provenance in every degree of population. Provenance is an opt-in tightening
// per catalog entry, so neither its absence nor a partially filled value may
// cause validation to fail.
func TestSkill_ValidateWithProvenance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		provenance  *Provenance
		expectError bool
	}{
		{
			name:       "no provenance",
			provenance: nil,
		},
		{
			name:       testCaseFullProvenance,
			provenance: fullProvenance(),
		},
		{
			// The five core Provenance fields have no omitempty, so this
			// serializes empty strings for everything but signer_identity.
			// The schema must tolerate that.
			name: "only signer identity",
			provenance: &Provenance{
				SignerIdentity: testSignerIdentity,
			},
		},
		{
			name:       "empty provenance object",
			provenance: &Provenance{},
		},
		{
			name: "provenance with attestation",
			provenance: &Provenance{
				SignerIdentity: testSignerIdentity,
				CertIssuer:     testCertIssuer,
				Attestation: &VerifiedAttestation{
					PredicateType: "https://slsa.dev/provenance/v1",
					Predicate:     map[string]any{"buildType": "workflow"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			skill := baseSkill()
			skill.Provenance = tc.provenance

			err := skill.Validate()
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestValidateSkillBytes_Provenance exercises the schema's provenance
// definition directly, including shapes the Go struct cannot express.
func TestValidateSkillBytes_Provenance(t *testing.T) {
	t.Parallel()

	const skillPrefix = `{
		"namespace": "io.github.stacklok",
		"name": "commit",
		"description": "Extract text and tables from PDF files",
		"version": "1.0.0"`

	tests := []struct {
		name        string
		provenance  string
		expectError bool
	}{
		{
			name:       "valid full provenance",
			provenance: `{"sigstore_url":"tuf-repo.github.com","repository_uri":"https://github.com/stacklok/dockyard","repository_ref":"refs/heads/main","signer_identity":"/.github/workflows/build-skills.yml","runner_environment":"github-hosted","cert_issuer":"https://token.actions.githubusercontent.com"}`, //nolint:lll
		},
		{
			name:       "valid partial provenance",
			provenance: `{"signer_identity":"/.github/workflows/build-skills.yml"}`,
		},
		{
			name:       "valid empty provenance object",
			provenance: `{}`,
		},
		{
			name:        "provenance must be an object",
			provenance:  `"not-an-object"`,
			expectError: true,
		},
		{
			name:        "signer_identity must be a string",
			provenance:  `{"signer_identity":42}`,
			expectError: true,
		},
		{
			name:        "attestation must be an object",
			provenance:  `{"attestation":"nope"}`,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			data := []byte(skillPrefix + `,"provenance":` + tc.provenance + "}")
			err := ValidateSkillBytes(data)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

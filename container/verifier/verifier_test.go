// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	registry "github.com/stacklok/toolhive-core/registry/types"
)

// ------ New ------

func TestNew_NilProvenance(t *testing.T) {
	t.Parallel()
	_, err := New(nil, nil)
	assert.ErrorIs(t, err, ErrProvenanceServerInformationNotSet)
}

// ------ WithKeychain ------

func TestWithKeychain_SetsKeychain(t *testing.T) {
	t.Parallel()
	s := &Sigstore{}
	kc := authn.NewMultiKeychain()
	got := s.WithKeychain(kc)
	assert.Same(t, s, got, "WithKeychain should return the same *Sigstore")
	assert.Equal(t, kc, s.keychain)
}

// ------ GetVerificationResults ------

// GetVerificationResults with an unparseable image reference should return an error
// (not ErrProvenanceNotFoundOrIncomplete, so the error propagates directly).
func TestGetVerificationResults_InvalidImageRef(t *testing.T) {
	t.Parallel()
	s := &Sigstore{keychain: authn.DefaultKeychain}
	results, err := s.GetVerificationResults("")
	assert.Error(t, err)
	assert.Nil(t, results)
}

// ------ VerifyServer ------

// VerifyServer propagates errors from GetVerificationResults.
func TestVerifyServer_PropagatesGetVerificationError(t *testing.T) {
	t.Parallel()
	s := &Sigstore{keychain: authn.DefaultKeychain}
	err := s.VerifyServer("", &registry.Provenance{})
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrImageNotSigned)
	assert.NotErrorIs(t, err, ErrProvenanceMismatch)
}

// VerifyServer with a nil provenance still calls GetVerificationResults first;
// if that errors the provenance nil-ness is irrelevant.
func TestVerifyServer_NilProvenance_InvalidRef(t *testing.T) {
	t.Parallel()
	s := &Sigstore{keychain: authn.DefaultKeychain}
	err := s.VerifyServer("", nil)
	require.Error(t, err)
}

// ------ isVerificationResultMatchingServerProvenance ------

// testSAN is a Fulcio-style subject alternative name. compareBaseProperties
// runs signerIdentityFromCertificate unconditionally, which errors on an empty
// SAN, so every fixture certificate carries one.
const testSAN = "https://github.com/stacklok/toolhive/.github/workflows/build.yml@refs/heads/main"

const (
	slsaPredicateType = "https://slsa.dev/provenance/v1"
	buildTypeKey      = "buildType"
	buildTypeGHA      = "gha"
	attemptKey        = "attempt"
)

// newTestResult builds a minimal verification result whose certificate is
// populated enough for compareBaseProperties to run cleanly.
func newTestResult(statement *in_toto.Statement) *verify.VerificationResult {
	return &verify.VerificationResult{
		Signature: &verify.SignatureVerificationResult{
			Certificate: &certificate.Summary{
				SubjectAlternativeName: testSAN,
			},
		},
		Statement: statement,
	}
}

// newTestStatement builds an in-toto statement. A nil predicate leaves
// Statement.Predicate nil, modelling a statement that carries no predicate.
func newTestStatement(t *testing.T, predicateType string, predicate map[string]any) *in_toto.Statement {
	t.Helper()
	stmt := &in_toto.Statement{PredicateType: predicateType}
	if predicate != nil {
		s, err := structpb.NewStruct(predicate)
		require.NoError(t, err)
		stmt.Predicate = s
	}
	return stmt
}

func TestIsVerificationResultMatchingServerProvenance_Attestation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		statement *in_toto.Statement
		expected  *registry.VerifiedAttestation
		want      bool
	}{
		{
			name:      "nil expected attestation is unconstrained",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA}),
			expected:  nil,
			want:      true,
		},
		{
			name:      "nil expected attestation with no statement is unconstrained",
			statement: nil,
			expected:  nil,
			want:      true,
		},
		{
			// Regression: this used to fall through to a match, skipping the
			// constraint exactly when the artifact carried no attestation.
			name:      "expected attestation but statement absent",
			statement: nil,
			expected:  &registry.VerifiedAttestation{PredicateType: slsaPredicateType},
			want:      false,
		},
		{
			name:      "empty expected attestation but statement absent",
			statement: nil,
			expected:  &registry.VerifiedAttestation{},
			want:      false,
		},
		{
			// An empty expectation means "must carry some attestation",
			// without constraining which one.
			name:      "empty expected attestation with statement present",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA}),
			expected:  &registry.VerifiedAttestation{},
			want:      true,
		},
		{
			name:      "predicate type matches, predicate unconstrained",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA}),
			expected:  &registry.VerifiedAttestation{PredicateType: slsaPredicateType},
			want:      true,
		},
		{
			name:      "predicate type mismatch",
			statement: newTestStatement(t, "https://slsa.dev/provenance/v0.2", map[string]any{buildTypeKey: buildTypeGHA}),
			expected:  &registry.VerifiedAttestation{PredicateType: slsaPredicateType},
			want:      false,
		},
		{
			name:      "expected predicate but statement carries none",
			statement: newTestStatement(t, slsaPredicateType, nil),
			expected: &registry.VerifiedAttestation{
				PredicateType: slsaPredicateType,
				Predicate:     map[string]any{buildTypeKey: buildTypeGHA},
			},
			want: false,
		},
		{
			name:      "predicate mismatch",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA}),
			expected: &registry.VerifiedAttestation{
				PredicateType: slsaPredicateType,
				Predicate:     map[string]any{buildTypeKey: "local"},
			},
			want: false,
		},
		{
			name: "predicate type and predicate both match",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{
				buildTypeKey: buildTypeGHA,
				"builder":    map[string]any{"id": "https://github.com/actions/runner"},
			}),
			expected: &registry.VerifiedAttestation{
				PredicateType: slsaPredicateType,
				Predicate: map[string]any{
					buildTypeKey: buildTypeGHA,
					"builder":    map[string]any{"id": "https://github.com/actions/runner"},
				},
			},
			want: true,
		},
		{
			name:      "predicate matches with predicate type unconstrained",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA}),
			expected:  &registry.VerifiedAttestation{Predicate: map[string]any{buildTypeKey: buildTypeGHA}},
			want:      true,
		},
		{
			// Documents the AsMap normalisation caveat: every number in a
			// statement predicate comes back as float64, matching how
			// encoding/json decodes the expected side but not YAML.
			name:      "numeric predicate matches as float64",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{attemptKey: 1}),
			expected:  &registry.VerifiedAttestation{Predicate: map[string]any{attemptKey: float64(1)}},
			want:      true,
		},
		{
			name:      "numeric predicate does not match as int",
			statement: newTestStatement(t, slsaPredicateType, map[string]any{attemptKey: 1}),
			expected:  &registry.VerifiedAttestation{Predicate: map[string]any{attemptKey: 1}},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := newTestResult(tt.statement)
			p := &registry.Provenance{Attestation: tt.expected}
			assert.Equal(t, tt.want, isVerificationResultMatchingServerProvenance(r, p))
		})
	}
}

func TestIsVerificationResultMatchingServerProvenance_Guards(t *testing.T) {
	t.Parallel()

	statement := newTestStatement(t, slsaPredicateType, map[string]any{buildTypeKey: buildTypeGHA})

	tests := []struct {
		name   string
		result *verify.VerificationResult
		prov   *registry.Provenance
		want   bool
	}{
		{
			name:   "nil result",
			result: nil,
			prov:   &registry.Provenance{},
			want:   false,
		},
		{
			name:   "nil provenance",
			result: newTestResult(statement),
			prov:   nil,
			want:   false,
		},
		{
			name:   "nil signature",
			result: &verify.VerificationResult{Statement: statement},
			prov:   &registry.Provenance{},
			want:   false,
		},
		{
			name: "nil certificate",
			result: &verify.VerificationResult{
				Signature: &verify.SignatureVerificationResult{},
				Statement: statement,
			},
			prov: &registry.Provenance{},
			want: false,
		},
		{
			// Base properties are checked before the attestation, so a
			// mismatch there short-circuits regardless of the attestation.
			name:   "base property mismatch short-circuits",
			result: newTestResult(statement),
			prov:   &registry.Provenance{RepositoryURI: "https://github.com/other/repo"},
			want:   false,
		},
		{
			name:   "no constraints at all",
			result: newTestResult(statement),
			prov:   &registry.Provenance{},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isVerificationResultMatchingServerProvenance(tt.result, tt.prov))
		})
	}
}

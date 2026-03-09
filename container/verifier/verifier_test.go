// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

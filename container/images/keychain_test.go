// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustResource(t *testing.T, registry string) authn.Resource {
	t.Helper()
	reg, err := name.NewRegistry(registry)
	require.NoError(t, err)
	return reg
}

func TestEnvKeychain_RegistrySpecific(t *testing.T) {
	t.Setenv("REGISTRY_GHCR_IO_USERNAME", "alice")
	t.Setenv("REGISTRY_GHCR_IO_PASSWORD", "s3cret")

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	require.NotEqual(t, authn.Anonymous, auth)

	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "alice", cfg.Username)
	assert.Equal(t, "s3cret", cfg.Password)
}

func TestEnvKeychain_NormalizesDashes(t *testing.T) {
	t.Setenv("REGISTRY_MY_REGISTRY_EXAMPLE_COM_USERNAME", "bob")
	t.Setenv("REGISTRY_MY_REGISTRY_EXAMPLE_COM_PASSWORD", "tok")

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "my-registry.example.com"))
	require.NoError(t, err)

	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "bob", cfg.Username)
	assert.Equal(t, "tok", cfg.Password)
}

func TestEnvKeychain_GenericFallback(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "generic-user")
	t.Setenv("REGISTRY_PASSWORD", "generic-pass")

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "registry.example.com"))
	require.NoError(t, err)

	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "generic-user", cfg.Username)
	assert.Equal(t, "generic-pass", cfg.Password)
}

func TestEnvKeychain_RegistrySpecificWinsOverGeneric(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "generic-user")
	t.Setenv("REGISTRY_PASSWORD", "generic-pass")
	t.Setenv("REGISTRY_GHCR_IO_USERNAME", "specific-user")
	t.Setenv("REGISTRY_GHCR_IO_PASSWORD", "specific-pass")

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)

	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "specific-user", cfg.Username)
}

func TestEnvKeychain_AnonymousWhenUnset(t *testing.T) {
	t.Parallel()

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
}

func TestEnvKeychain_AnonymousWhenPartiallySet(t *testing.T) {
	t.Setenv("REGISTRY_GHCR_IO_USERNAME", "alice")
	// no password

	auth, err := (&envKeychain{}).Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
}

type fixedKeychain struct {
	auth authn.Authenticator
	err  error
}

func (k *fixedKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return k.auth, k.err
}

func TestCompositeKeychain_FirstNonAnonymousWins(t *testing.T) {
	t.Parallel()

	specific := &authn.Basic{Username: "u", Password: "p"}
	kc := &compositeKeychain{keychains: []authn.Keychain{
		&fixedKeychain{auth: authn.Anonymous},
		&fixedKeychain{auth: specific},
	}}

	auth, err := kc.Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, specific, auth)
}

func TestCompositeKeychain_SkipsErrors(t *testing.T) {
	t.Parallel()

	specific := &authn.Basic{Username: "u", Password: "p"}
	kc := &compositeKeychain{keychains: []authn.Keychain{
		&fixedKeychain{err: assert.AnError},
		&fixedKeychain{auth: specific},
	}}

	auth, err := kc.Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, specific, auth)
}

func TestCompositeKeychain_AllAnonymous(t *testing.T) {
	t.Parallel()

	kc := &compositeKeychain{keychains: []authn.Keychain{
		&fixedKeychain{auth: authn.Anonymous},
		&fixedKeychain{auth: authn.Anonymous},
	}}

	auth, err := kc.Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
}

func TestNewCompositeKeychain_EnvFirst(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "env-user")
	t.Setenv("REGISTRY_PASSWORD", "env-pass")

	auth, err := NewCompositeKeychain().Resolve(mustResource(t, "ghcr.io"))
	require.NoError(t, err)

	cfg, err := auth.Authorization()
	require.NoError(t, err)
	assert.Equal(t, "env-user", cfg.Username, "env credentials must win over the default keychain")
}

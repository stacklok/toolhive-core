// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package server provides configuration loading utilities for the ToolHive config server.
package server

import (
	"errors"

	"github.com/stacklok/toolhive-core/env"
)

// Environment variable names for OIDC / IDP configuration.
const (
	EnvIssuer        = "CONFIG_SERVER_ISSUER"
	EnvAudience      = "CONFIG_SERVER_AUDIENCE"
	EnvRequiredScope = "CONFIG_SERVER_REQUIRED_SCOPE"
)

// DefaultRequiredScope is the OIDC scope required when CONFIG_SERVER_REQUIRED_SCOPE is absent.
const DefaultRequiredScope = "openid"

// IDPConfig holds the OIDC identity-provider settings read from the environment.
type IDPConfig struct {
	Issuer        string
	Audience      string
	RequiredScope string
}

// lookupEnvReader is an optional extension of env.Reader that distinguishes a
// variable that is absent (returns "", false) from one that is set to ""
// (returns "", true). Map-backed test doubles satisfy this automatically via
// the two-value map lookup; production code should use OSLookupReader.
type lookupEnvReader interface {
	env.Reader
	Lookupenv(key string) (string, bool)
}

// LoadIDPConfig reads OIDC settings from environment variables via r.
//
// CONFIG_SERVER_REQUIRED_SCOPE is handled with absent-vs-empty semantics when r
// implements lookupEnvReader: absent → DefaultRequiredScope, present-but-empty →
// scope checking disabled. Without lookupEnvReader an empty value falls back to
// DefaultRequiredScope.
// Returns an error if CONFIG_SERVER_ISSUER or CONFIG_SERVER_AUDIENCE are empty.
func LoadIDPConfig(r env.Reader) (IDPConfig, error) {
	issuer := r.Getenv(EnvIssuer)
	if issuer == "" {
		return IDPConfig{}, errors.New("CONFIG_SERVER_ISSUER is required but not set")
	}

	audience := r.Getenv(EnvAudience)
	if audience == "" {
		return IDPConfig{}, errors.New("CONFIG_SERVER_AUDIENCE is required but not set")
	}

	requiredScope := resolveRequiredScope(r)

	return IDPConfig{
		Issuer:        issuer,
		Audience:      audience,
		RequiredScope: requiredScope,
	}, nil
}

// resolveRequiredScope applies absent-vs-empty semantics for CONFIG_SERVER_REQUIRED_SCOPE.
func resolveRequiredScope(r env.Reader) string {
	if lr, ok := r.(lookupEnvReader); ok {
		val, present := lr.Lookupenv(EnvRequiredScope)
		if !present {
			return DefaultRequiredScope
		}
		return val // present-but-empty disables scope checking
	}
	// Fallback: cannot distinguish absent from empty; treat empty as default.
	if val := r.Getenv(EnvRequiredScope); val != "" {
		return val
	}
	return DefaultRequiredScope
}

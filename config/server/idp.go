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

// LoadIDPConfig reads OIDC settings from environment variables via r.
//
// CONFIG_SERVER_REQUIRED_SCOPE uses absent-vs-empty semantics via env.Reader.LookupEnv:
// absent → DefaultRequiredScope, present-but-empty → scope checking disabled.
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

	requiredScope, present := r.LookupEnv(EnvRequiredScope)
	if !present {
		requiredScope = DefaultRequiredScope
	}

	return IDPConfig{
		Issuer:        issuer,
		Audience:      audience,
		RequiredScope: requiredScope,
	}, nil
}

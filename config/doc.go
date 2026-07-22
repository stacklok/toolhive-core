// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package config provides a small, embeddable base configuration shared by
ToolHive-ecosystem services, plus a strict YAML loader for it.

# Scope

This package only owns fields that are truly universal across services:
service identity, logging, and deployment environment. It does not define
per-service schema (database DSNs, upstream URLs, feature flags, etc.) —
those belong in each consuming service's own config struct. It also does
not impose a fixed vocabulary for values that vary by deployment, such as
Environment — those stay freeform strings.

# Basic Usage

A service defines its own config struct and embeds [BaseConfig] inline so
the base fields decode at the top level of the YAML document alongside the
service's own fields:

	type Config struct {
		config.BaseConfig `yaml:",inline"`

		Gateway GatewayConfig `yaml:"gateway"`
	}

	type GatewayConfig struct {
		ID string `yaml:"id"`
	}

	var cfg Config
	if err := config.Load("service.yaml", &cfg); err != nil {
		// handle error
	}

# Validation

[BaseConfig.Validate] checks only the base fields. Each service should call
it from its own Validate method, then add its own cross-field checks:

	func (c *Config) Validate() error {
		if err := c.BaseConfig.Validate(); err != nil {
			return err
		}
		if c.Gateway.ID == "" {
			return errors.New("gateway.id is required")
		}
		return nil
	}

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package config

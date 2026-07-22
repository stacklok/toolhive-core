// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"gopkg.in/yaml.v3"
)

// BaseConfig holds configuration fields common to every ToolHive-ecosystem
// service. Consuming services embed it inline in their own config struct
// rather than referencing it as a nested field, so the fields decode at the
// top level of the YAML document:
//
//	type Config struct {
//		config.BaseConfig `yaml:",inline"`
//		// service-specific fields below
//	}
type BaseConfig struct {
	// ServiceName identifies the service in logs, metrics, and traces.
	// Required.
	ServiceName string `yaml:"serviceName"`

	// LogLevel is the minimum log level: "debug", "info", "warn", or
	// "error". Defaults to "info" when empty.
	LogLevel string `yaml:"logLevel"`

	// Environment identifies the deployment tier a service is running in
	// (e.g. "dev", "staging", "prod"). Deployments name their environments
	// differently, so this is a freeform string with no fixed set of
	// values and no validation.
	Environment string `yaml:"env"`
}

// Validate checks the base fields and returns the first violation
// encountered. It does not know about, and does not validate, any fields a
// consuming service adds alongside it.
func (c *BaseConfig) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.ServiceName == "" {
		return errors.New("serviceName is required")
	}
	if _, err := c.SlogLevel(); err != nil {
		return err
	}
	return nil
}

// SlogLevel parses LogLevel into a [log/slog.Level]. An empty LogLevel
// resolves to [log/slog.LevelInfo].
func (c *BaseConfig) SlogLevel() (slog.Level, error) {
	switch c.LogLevel {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logLevel: unknown level %q", c.LogLevel)
	}
}

// Load reads the YAML file at path and decodes it into cfg. Decoding is
// strict: unknown fields anywhere in the document are rejected, including
// fields under a service's own sections. This is the same behavior
// consuming services get by hand-rolling yaml.NewDecoder(...).KnownFields
// (true); Load exists so every service gets it uniformly.
//
// Load does not call Validate — callers validate explicitly after loading,
// since only the caller's concrete config type knows its own required
// fields.
func Load[T any](path string, cfg *T) error {
	f, err := os.Open(path) //#nosec G304 -- path is caller-provided config location, not user input
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer func() { _ = f.Close() }()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("decode config file %s: %w", path, err)
	}
	return nil
}

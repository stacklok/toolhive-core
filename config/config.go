// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io"
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

// validLogLevels are the LogLevel values Validate accepts. This package
// deliberately has no dependency on log/slog or any other logging
// package — it only knows these are valid strings; parsing a level name
// into a concrete logger's level type is that logger's job (see, e.g.,
// the sibling logging package's ParseLevel).
var validLogLevels = map[string]bool{
	"":      true,
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
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
	if !validLogLevels[c.LogLevel] {
		return fmt.Errorf("logLevel: unknown level %q", c.LogLevel)
	}
	return nil
}

// decodeOptions holds the resolved options for [Load] and [Decode].
type decodeOptions struct {
	strict bool
}

// Option configures [Load] and [Decode].
type Option func(*decodeOptions)

// AllowUnknownFields disables strict decoding, so unknown fields in the
// YAML document are silently ignored instead of rejected. The default
// behavior (no options) is strict.
//
// Prefer leaving decoding strict where possible — it catches typos in
// field names that would otherwise fail silently. Use this only when a
// consumer genuinely needs to tolerate fields it doesn't know about yet
// (e.g. a rolling deploy reading a config written by a newer version).
func AllowUnknownFields() Option {
	return func(o *decodeOptions) {
		o.strict = false
	}
}

// Load reads the YAML file at path and decodes it into cfg. See [Decode]
// for the decoding behavior.
//
// Load does not call Validate — callers validate explicitly after loading,
// since only the caller's concrete config type knows its own required
// fields.
func Load[T any](path string, cfg *T, opts ...Option) error {
	f, err := os.Open(path) //#nosec G304 -- path is caller-provided config location, not user input
	if err != nil {
		return fmt.Errorf("open config file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := Decode(f, cfg, opts...); err != nil {
		return fmt.Errorf("decode config file %s: %w", path, err)
	}
	return nil
}

// Decode reads YAML from r and decodes it into cfg. By default, decoding
// is strict: unknown fields anywhere in the document are rejected,
// including fields under a service's own sections. This is the same
// behavior consuming services get by hand-rolling
// yaml.NewDecoder(...).KnownFields(true); Decode exists so every service
// gets it uniformly. Pass [AllowUnknownFields] to relax this.
//
// Use Decode directly (rather than [Load]) when the config doesn't come
// from a plain file path — an embedded FS, a remote fetch, or an in-memory
// byte slice in a test.
func Decode[T any](r io.Reader, cfg *T, opts ...Option) error {
	o := decodeOptions{strict: true}
	for _, opt := range opts {
		opt(&o)
	}

	dec := yaml.NewDecoder(r)
	dec.KnownFields(o.strict)
	if err := dec.Decode(cfg); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return nil
}

// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stacklok/toolhive-core/config"
)

const (
	levelDebug  = "debug"
	serviceName = "gateway"
)

func TestBaseConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     config.BaseConfig
		wantErr string
	}{
		{
			name: "valid with explicit level",
			cfg:  config.BaseConfig{ServiceName: serviceName, LogLevel: levelDebug},
		},
		{
			name: "valid with empty level defaults to info",
			cfg:  config.BaseConfig{ServiceName: serviceName},
		},
		{
			name:    "missing service name",
			cfg:     config.BaseConfig{LogLevel: "info"},
			wantErr: "serviceName is required",
		},
		{
			name:    "unknown log level",
			cfg:     config.BaseConfig{ServiceName: serviceName, LogLevel: "verbose"},
			wantErr: `logLevel: unknown level "verbose"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("Validate() = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestBaseConfig_SlogLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		level   string
		want    slog.Level
		wantErr bool
	}{
		{level: "", want: slog.LevelInfo},
		{level: "info", want: slog.LevelInfo},
		{level: levelDebug, want: slog.LevelDebug},
		{level: "warn", want: slog.LevelWarn},
		{level: "error", want: slog.LevelError},
		{level: "bogus", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			t.Parallel()

			c := config.BaseConfig{LogLevel: tt.level}
			got, err := c.SlogLevel()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("SlogLevel(%q) = nil error, want error", tt.level)
				}
				return
			}
			if err != nil {
				t.Fatalf("SlogLevel(%q) = %v, want nil error", tt.level, err)
			}
			if got != tt.want {
				t.Fatalf("SlogLevel(%q) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

// serviceConfig mimics a consuming service's config: the shared base fields
// embedded inline, plus fields only that service knows about.
type serviceConfig struct {
	config.BaseConfig `yaml:",inline"`

	Gateway gatewayConfig `yaml:"gateway"`
}

type gatewayConfig struct {
	ID string `yaml:"id"`
}

func (c *serviceConfig) Validate() error {
	if err := c.BaseConfig.Validate(); err != nil {
		return err
	}
	if c.Gateway.ID == "" {
		return &fieldError{"gateway.id is required"}
	}
	return nil
}

type fieldError struct{ msg string }

func (e *fieldError) Error() string { return e.msg }

func TestLoad_ExtendedServiceConfig(t *testing.T) {
	t.Parallel()

	path := writeYAML(t, `
serviceName: airlock-gateway
logLevel: debug
gateway:
  id: gw-1
`)

	var cfg serviceConfig
	if err := config.Load(path, &cfg); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	if cfg.ServiceName != "airlock-gateway" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "airlock-gateway")
	}
	if cfg.LogLevel != levelDebug {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, levelDebug)
	}
	if cfg.Gateway.ID != "gw-1" {
		t.Errorf("Gateway.ID = %q, want %q", cfg.Gateway.ID, "gw-1")
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	t.Parallel()

	path := writeYAML(t, `
serviceName: airlock-gateway
gateway:
  id: gw-1
  typoField: oops
`)

	var cfg serviceConfig
	err := config.Load(path, &cfg)
	if err == nil {
		t.Fatal("Load() = nil error, want error for unknown field")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	t.Parallel()

	var cfg serviceConfig
	err := config.Load(filepath.Join(t.TempDir(), "missing.yaml"), &cfg)
	if err == nil {
		t.Fatal("Load() = nil error, want error for missing file")
	}
}

func writeYAML(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

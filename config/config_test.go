// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stacklok/toolhive-core/config"
)

const (
	levelDebug  = "debug"
	serviceName = "gateway"
	gatewayID   = "gw-1"
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
			name: "valid with warn level",
			cfg:  config.BaseConfig{ServiceName: serviceName, LogLevel: "warn"},
		},
		{
			name: "valid with error level",
			cfg:  config.BaseConfig{ServiceName: serviceName, LogLevel: "error"},
		},
		{
			name: "valid with freeform environment",
			cfg:  config.BaseConfig{ServiceName: serviceName, Environment: "qa-shared-3"},
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
env: staging
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
	if cfg.Environment != "staging" {
		t.Errorf("Environment = %q, want %q", cfg.Environment, "staging")
	}
	if cfg.Gateway.ID != gatewayID {
		t.Errorf("Gateway.ID = %q, want %q", cfg.Gateway.ID, gatewayID)
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

func TestLoad_AllowUnknownFields(t *testing.T) {
	t.Parallel()

	path := writeYAML(t, `
serviceName: airlock-gateway
gateway:
  id: gw-1
  typoField: oops
`)

	var cfg serviceConfig
	if err := config.Load(path, &cfg, config.AllowUnknownFields()); err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if cfg.Gateway.ID != gatewayID {
		t.Errorf("Gateway.ID = %q, want %q", cfg.Gateway.ID, gatewayID)
	}
}

func TestDecode_ReaderBased(t *testing.T) {
	t.Parallel()

	r := strings.NewReader(`
serviceName: airlock-gateway
gateway:
  id: gw-1
`)

	var cfg serviceConfig
	if err := config.Decode(r, &cfg); err != nil {
		t.Fatalf("Decode() = %v, want nil", err)
	}
	if cfg.ServiceName != "airlock-gateway" {
		t.Errorf("ServiceName = %q, want %q", cfg.ServiceName, "airlock-gateway")
	}
	if cfg.Gateway.ID != gatewayID {
		t.Errorf("Gateway.ID = %q, want %q", cfg.Gateway.ID, gatewayID)
	}
}

func TestDecode_UnknownFieldRejectedByDefault(t *testing.T) {
	t.Parallel()

	r := strings.NewReader(`
serviceName: airlock-gateway
gateway:
  id: gw-1
  typoField: oops
`)

	var cfg serviceConfig
	if err := config.Decode(r, &cfg); err == nil {
		t.Fatal("Decode() = nil error, want error for unknown field")
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

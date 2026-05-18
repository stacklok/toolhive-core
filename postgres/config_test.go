// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	return &Config{
		Host:     "db.example.com",
		Port:     5432,
		User:     testUser,
		Password: "s3cret",
		Database: "appdb",
	}
}

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name:    testCaseNilConfig,
			cfg:     nil,
			wantErr: testErrConfigNil,
		},
		{
			name:    "missing host",
			cfg:     &Config{Port: 5432, User: "u", Database: "d"},
			wantErr: "host is required",
		},
		{
			name:    "missing port",
			cfg:     &Config{Host: "h", User: "u", Database: "d"},
			wantErr: "port is required",
		},
		{
			name:    "missing user",
			cfg:     &Config{Host: "h", Port: 5432, Database: "d"},
			wantErr: "user is required",
		},
		{
			name:    "missing database",
			cfg:     &Config{Host: "h", Port: 5432, User: "u"},
			wantErr: "database is required",
		},
		{
			name: testCaseNoBackend,
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{},
			},
			wantErr: testErrNoSupportedAuth,
		},
		{
			name: "AWS RDS IAM without region",
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{
					AWSRDSIAM: &DynamicAuthAWSRDSIAM{},
				},
			},
			wantErr: testErrRegionConfigured,
		},
		{
			name: "valid minimal config",
			cfg:  validConfig(),
		},
		{
			name: "valid with AWS RDS IAM",
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{
					AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: "us-east-1"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestConfig_BuildConnectionStringWithAuth(t *testing.T) {
	t.Parallel()

	t.Run("includes password when set", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Host: "h", Port: 5432, Database: "d"}
		got := cfg.BuildConnectionStringWithAuth("alice", "p@ss/word")
		// url.UserPassword percent-encodes special chars.
		assert.Equal(t, "postgres://alice:p%40ss%2Fword@h:5432/d?sslmode=require", got)
	})

	t.Run("omits credentials when password empty", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Host: "h", Port: 5432, Database: "d"}
		got := cfg.BuildConnectionStringWithAuth("alice", "")
		assert.Equal(t, "postgres://alice@h:5432/d?sslmode=require", got)
	})

	t.Run("honors custom SSL mode", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Host: "h", Port: 5432, Database: "d", SSLMode: testSSLModeDisable}
		got := cfg.BuildConnectionStringWithAuth("u", "")
		assert.Contains(t, got, "sslmode="+testSSLModeDisable)
	})
}

func TestConfig_MigrationHelpers(t *testing.T) {
	t.Parallel()

	t.Run("falls back to User and Password when migration fields unset", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		assert.Equal(t, testUser, cfg.GetMigrationUser())
		assert.Equal(t, "s3cret", cfg.GetMigrationPassword())
		assert.Equal(t, cfg.ConnectionString(), cfg.MigrationConnectionString())
	})

	t.Run("uses MigrationUser and shares Password when users match", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.MigrationUser = testUser // same as User
		assert.Equal(t, "s3cret", cfg.GetMigrationPassword())
	})

	t.Run("distinct migration user without password falls back to pgpass", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.MigrationUser = "migrator"
		assert.Equal(t, "migrator", cfg.GetMigrationUser())
		assert.Empty(t, cfg.GetMigrationPassword())
		got := cfg.MigrationConnectionString()
		assert.Equal(t, "postgres://migrator@db.example.com:5432/appdb?sslmode=require", got)
	})

	t.Run("explicit migration password wins", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.MigrationUser = "migrator"
		cfg.MigrationPassword = "elev8"
		assert.Equal(t, "elev8", cfg.GetMigrationPassword())
	})
}

func TestConfig_LogValueRedactsSecrets(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Host:              "db.example.com",
		Port:              5432,
		User:              testUser,
		Password:          "should-not-appear",
		MigrationPassword: "should-not-appear-either",
		Database:          "appdb",
		SSLMode:           "require",
		DynamicAuth:       &DynamicAuthConfig{AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: "us-east-1"}},
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.LogAttrs(context.Background(), slog.LevelInfo, "db", slog.Any("cfg", cfg))

	out := buf.String()
	assert.NotContains(t, out, "should-not-appear")
	assert.Contains(t, out, `"has_password":true`)
	assert.Contains(t, out, `"has_migration_password":true`)
	assert.Contains(t, out, `"dynamic_auth":true`)
	assert.Contains(t, out, `"host":"db.example.com"`)
}

func TestConfig_LogValueNil(t *testing.T) {
	t.Parallel()
	var cfg *Config
	// Should not panic.
	got := cfg.LogValue()
	assert.Equal(t, slog.Value{}, got)
}

func TestConfig_ConnMaxLifetimeIsSlot(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.ConnMaxLifetime = 30 * time.Minute
	require.NoError(t, cfg.Validate())
	assert.Equal(t, 30*time.Minute, cfg.ConnMaxLifetime)
}

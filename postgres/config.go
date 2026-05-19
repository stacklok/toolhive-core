// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
)

// Characters rejected in Host and Database to prevent DSN-string injection
// when these values flow into a libpq URL. Host disallows the URL
// delimiters that could shift the authority section; Database disallows
// the delimiters that could shift the query section.
const (
	hostForbiddenChars     = "@/?#"
	databaseForbiddenChars = "?#/"
)

// DefaultSSLMode is applied by BuildConnectionStringWithAuth when Config.SSLMode
// is empty. "require" is the safe production default: encryption is mandatory
// but the server certificate is not validated against a CA. Callers that need
// stricter behavior should set SSLMode to "verify-ca" or "verify-full".
const DefaultSSLMode = "require"

// Config configures a PostgreSQL connection pool. Password fields are
// resolved by the caller — file-based secrets, environment variables, and
// pgpass fallback all live outside this package.
type Config struct {
	// Host is the database server hostname or IP address.
	Host string

	// Port is the database server port. Required.
	Port int

	// User is the database username for normal operations
	// (SELECT/INSERT/UPDATE/DELETE).
	User string

	// Password is the application-user password. When empty, pgx falls back
	// to PGPASSFILE / ~/.pgpass. Mutually exclusive with DynamicAuth at the
	// caller's option — this package does not enforce mutual exclusion
	// because some callers legitimately want a static fallback during local
	// development.
	Password string //nolint:gosec // G101: field name, not a hardcoded credential

	// MigrationUser is the database username for schema migrations. When
	// empty, defaults to User.
	MigrationUser string

	// MigrationPassword is the password for MigrationUser. When empty and
	// MigrationUser equals User, falls back to Password. Otherwise pgx falls
	// back to PGPASSFILE / ~/.pgpass.
	MigrationPassword string //nolint:gosec // G101: field name, not a hardcoded credential

	// Database is the database name.
	Database string

	// SSLMode is the SSL mode for the connection (disable, require, verify-ca,
	// verify-full). When empty, DefaultSSLMode is applied by the connection
	// string builder.
	SSLMode string

	// DynamicAuth, when non-nil, generates short-lived credentials at connect
	// time via NewPool's automatically-installed BeforeConnect hook.
	DynamicAuth *DynamicAuthConfig

	// MaxOpenConns sets the upper bound on open connections in the pool. When
	// zero, pgxpool's default is used.
	MaxOpenConns int32

	// MinConns is the minimum number of connections pgxpool actively
	// maintains in the pool — the pool keeps this many connections open
	// even when the application is idle. When zero, pgxpool's default is
	// used.
	//
	// Note for readers used to database/sql: this is the opposite of
	// database/sql's MaxIdleConns (which is a ceiling on idle
	// connections). pgxpool has no idle-ceiling concept; the floor is the
	// only knob.
	MinConns int32

	// ConnMaxLifetime is the maximum lifetime of a connection. When zero,
	// pgxpool's default is used.
	ConnMaxLifetime time.Duration
}

// DynamicAuthConfig selects a dynamic-authentication backend. Exactly one
// backend field must be non-nil when DynamicAuthConfig itself is non-nil.
type DynamicAuthConfig struct {
	// AWSRDSIAM enables AWS RDS IAM authentication tokens.
	AWSRDSIAM *DynamicAuthAWSRDSIAM
}

// DynamicAuthAWSRDSIAM configures AWS RDS IAM dynamic authentication.
type DynamicAuthAWSRDSIAM struct {
	// Region is the AWS region used to sign IAM tokens. Use "detect" to
	// auto-discover the region from the EC2 instance metadata service (IMDS).
	Region string
}

// Validate checks Config for required-field and consistency errors and
// returns the first violation encountered.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.Host == "" {
		return errors.New("host is required")
	}
	if strings.ContainsAny(c.Host, hostForbiddenChars) || strings.ContainsAny(c.Host, " \t\r\n") {
		return fmt.Errorf("host must not contain any of %q or whitespace", hostForbiddenChars)
	}
	if c.Port <= 0 || c.Port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if c.User == "" {
		return errors.New("user is required")
	}
	if c.Database == "" {
		return errors.New("database is required")
	}
	if strings.ContainsAny(c.Database, databaseForbiddenChars) || strings.ContainsAny(c.Database, " \t\r\n") {
		return fmt.Errorf("database must not contain any of %q or whitespace", databaseForbiddenChars)
	}
	if c.DynamicAuth != nil {
		if c.DynamicAuth.AWSRDSIAM == nil {
			return errors.New("dynamicAuth is set but no supported auth method (e.g., awsRdsIam) is configured")
		}
		if c.DynamicAuth.AWSRDSIAM.Region == "" {
			return errors.New("dynamicAuth.awsRdsIam.region is required")
		}
	}
	return nil
}

// LogValue implements slog.LogValuer. It redacts password fields and reports
// only presence-indicators for credentials, preventing accidental secret
// disclosure in logs.
func (c *Config) LogValue() slog.Value {
	if c == nil {
		return slog.Value{}
	}
	return slog.GroupValue(
		slog.String("host", c.Host),
		slog.Int("port", c.Port),
		slog.String("user", c.User),
		slog.String("database", c.Database),
		slog.String("ssl_mode", c.SSLMode),
		slog.Bool("has_password", c.Password != ""),
		slog.Bool("has_migration_password", c.MigrationPassword != ""),
		slog.Bool("dynamic_auth", c.DynamicAuth != nil),
	)
}

// GetMigrationUser returns the user that owns schema migrations. Falls back
// to User when MigrationUser is unset.
func (c *Config) GetMigrationUser() string {
	if c.MigrationUser != "" {
		return c.MigrationUser
	}
	return c.User
}

// GetMigrationPassword returns the password for the migration user. When
// MigrationPassword is unset and the migration user matches User, the
// application Password is returned. Otherwise an empty string is returned so
// pgx can fall back to PGPASSFILE / ~/.pgpass.
func (c *Config) GetMigrationPassword() string {
	if c.MigrationPassword != "" {
		return c.MigrationPassword
	}
	if c.GetMigrationUser() == c.User {
		return c.Password
	}
	return ""
}

// ConnectionString builds a libpq-style connection URL for the application
// user. When Password is empty, pgx falls back to PGPASSFILE / ~/.pgpass.
func (c *Config) ConnectionString() string {
	return c.BuildConnectionStringWithAuth(c.User, c.Password)
}

// MigrationConnectionString builds a libpq-style connection URL for the
// migration user. Useful for short-lived migration tooling where a
// BeforeConnect hook is not available.
func (c *Config) MigrationConnectionString() string {
	return c.BuildConnectionStringWithAuth(c.GetMigrationUser(), c.GetMigrationPassword())
}

// BuildConnectionStringWithAuth builds a libpq-style connection URL using
// the supplied user and password. When password is empty, the resulting URL
// omits credentials and pgx will fall back to PGPASSFILE / ~/.pgpass.
//
// The caller is responsible for resolving credentials — dynamic-auth token
// generation, secret-file reads, and env-var overrides all happen outside
// this package.
func (c *Config) BuildConnectionStringWithAuth(user, password string) string {
	sslMode := c.SSLMode
	if sslMode == "" {
		sslMode = DefaultSSLMode
	}

	var userInfo *url.Userinfo
	if password != "" {
		userInfo = url.UserPassword(user, password)
	} else {
		userInfo = url.User(user)
	}

	return fmt.Sprintf(
		"postgres://%s@%s:%d/%s?sslmode=%s",
		userInfo.String(),
		c.Host,
		c.Port,
		c.Database,
		sslMode,
	)
}

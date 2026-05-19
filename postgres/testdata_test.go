// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

const (
	testUser                = "appuser"
	testCaseNilConfig       = "nil config"
	testErrConfigNil        = "config is nil"
	testCaseNoBackend       = "dynamic auth without backend"
	testErrNoSupportedAuth  = "no supported auth method"
	testSSLModeDisable      = "disable"
	testErrRegionMissing    = "AWS RDS IAM region is not configured"
	testErrRegionConfigured = "dynamicAuth.awsRdsIam.region is required"
	testDatabase            = "appdb"
)

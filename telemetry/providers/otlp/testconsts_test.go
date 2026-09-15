// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

// Shared test fixtures, extracted to satisfy goconst.
const (
	testEndpointLocal    = "localhost:4318"
	testEndpointLangfuse = "cloud.langfuse.com/api/public/otel"
	testLangfuseHost     = "cloud.langfuse.com"
	testLangfusePath     = "/api/public/otel"
	testAuthHeader       = "Authorization"
	testSecretValue      = "secret"
	testBasicCred        = "Basic abc123"
	testAPIKeyHeader     = "x-api-key"
	testBearerToken      = "Bearer token"
	testNameValid        = "valid config"
	testNameCustomPath   = "endpoint with custom path"
	testEnvHeaderKey     = "x-env"
	testInvalidCACert    = "/nonexistent/ca.crt"

	testNameProtocolUnsetDefaultsHTTP = "unset protocol defaults to http/protobuf (backward compat)"
	testNameProtocolExplicitHTTP      = "explicit http/protobuf"
	testNameProtocolGRPC              = "grpc selects the gRPC exporter"
)

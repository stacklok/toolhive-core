// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package converters

const (
	testVersion     = "1.0.0"
	testLastUpdated = "2024-01-01T00:00:00Z"

	testImageRef          = "ghcr.io/test/server:latest"
	testNamespace         = "io.github.stacklok"
	testServerNameFetchFQ = "io.github.stacklok/fetch"
	testServerNameFetch   = "fetch"

	testName        = "test"
	testTier        = "Official"
	testToolName    = "tool1"
	testToolNameAlt = "tool2"
	testCategory    = "example"

	testTransportSSE = "sse"
	testRemoteURL    = "https://api.example.com/mcp"

	tierKey  = "tier"
	toolsKey = "tools"

	envAPIKey       = "API_KEY"
	envDebug        = "DEBUG"
	envToken        = "TOKEN"
	envValueDefault = "default-key"
	envValueTrue    = "true"
	envTokenTpl     = "TOKEN={token}"
	valueToken      = "token"

	envDescAPIKey    = "API key"
	envDescAuthToken = "Auth token"
	envDescRuntime   = "Set an environment variable in the runtime"
)

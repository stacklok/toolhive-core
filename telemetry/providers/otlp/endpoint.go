// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"fmt"
	"net/url"
	"strings"
)

// Default URL path suffixes for the OTLP/HTTP protocol, as defined in the
// OpenTelemetry specification:
// https://opentelemetry.io/docs/specs/otlp/#otlphttp-request
//
// The Go OTLP SDK normally appends these automatically. However, when the user
// provides a custom base path (e.g. "/api/public/otel" for Langfuse), we must
// call WithURLPath which replaces the entire path. In that case we concatenate
// the base path with the appropriate suffix ourselves (e.g.
// "/api/public/otel" + "/v1/traces").
const (
	otlpTracesPath  = "/v1/traces"
	otlpMetricsPath = "/v1/metrics"
	otlpLogsPath    = "/v1/logs"
)

// splitEndpointPath separates an OTLP endpoint string into its host:port and
// path components. If no path is present, basePath is empty.
//
// The function defensively strips http:// and https:// prefixes so it works
// correctly even when the scheme has not been removed upstream (e.g. the CLI
// path, which does not call NormalizeTelemetryConfig).
func splitEndpointPath(endpoint string) (hostPort, basePath string) {
	endpoint = strings.TrimPrefix(endpoint, "https://")
	endpoint = strings.TrimPrefix(endpoint, "http://")

	idx := strings.Index(endpoint, "/")
	if idx < 0 {
		return endpoint, ""
	}
	return endpoint[:idx], strings.TrimRight(endpoint[idx:], "/")
}

// validateTracesEndpoint checks that an exact traces URL is one the OTLP/HTTP
// exporter will honor as given. The SDK's WithEndpointURL logs a URL it cannot
// parse and carries on with its defaults, and drops a query string without a
// word, so either would otherwise send traces somewhere other than where the
// caller pointed them.
func validateTracesEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid traces endpoint %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid traces endpoint %q: scheme must be http or https", raw)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid traces endpoint %q: missing host", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid traces endpoint %q: query and fragment are not supported", raw)
	}
	return nil
}

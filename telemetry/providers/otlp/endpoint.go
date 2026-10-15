// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"errors"
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
// parse and carries on with its defaults, silently drops a query string and
// userinfo, and rebuilds the request from the decoded path, so any of those
// would otherwise send traces somewhere other than where the caller pointed
// them.
//
// The returned errors never quote the URL or wrap url.Parse's error, which
// does: an endpoint can carry a credential in its path, query or userinfo, and
// these errors end up in logs.
func validateTracesEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("invalid traces endpoint: not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("invalid traces endpoint: scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("invalid traces endpoint: missing host")
	}
	if u.User != nil {
		return errors.New("invalid traces endpoint: credentials in the URL are not supported, pass them as headers")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return errors.New("invalid traces endpoint: query and fragment are not supported")
	}
	if sdkRequestPath(u) != requestedPath(u) {
		return errors.New("invalid traces endpoint: path would not be sent as written " +
			"(escaped characters the exporter decodes, or surrounding whitespace)")
	}
	return nil
}

// requestedPath is the escaped path exactly as the caller wrote it, with an
// empty path meaning the root.
func requestedPath(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// sdkRequestPath is the escaped path otlptracehttp will actually request for
// u. WithEndpointURL keeps only the decoded u.Path, the SDK trims surrounding
// whitespace from it and defaults an empty one to the root, and the request is
// rebuilt from that decoded path, so e.g. "%2F" comes out as "/".
func sdkRequestPath(u *url.URL) string {
	p := strings.TrimSpace(u.Path)
	if p == "" || p == "." {
		p = "/"
	}
	return (&url.URL{Path: p}).EscapedPath()
}

// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

// LoggingLevel represents the severity of a log message.
//
// These map to syslog message severities, as specified in RFC-5424:
// https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1
type LoggingLevel string

// MCP logging levels.
const (
	LoggingLevelDebug     LoggingLevel = "debug"
	LoggingLevelInfo      LoggingLevel = "info"
	LoggingLevelNotice    LoggingLevel = "notice"
	LoggingLevelWarning   LoggingLevel = "warning"
	LoggingLevelError     LoggingLevel = "error"
	LoggingLevelCritical  LoggingLevel = "critical"
	LoggingLevelAlert     LoggingLevel = "alert"
	LoggingLevelEmergency LoggingLevel = "emergency"
)

// SetLevelRequest is a request from the client to the server, to enable or
// adjust logging.
type SetLevelRequest struct {
	Request
	Params SetLevelParams `json:"params"`
	Header http.Header    `json:"-"`
}

// SetLevelParams carries the level for a SetLevelRequest.
type SetLevelParams struct {
	// The level of logging that the client wants to receive from the server.
	// The server should send all logs at this level and higher (i.e., more severe) to
	// the client as notifications/logging/message.
	Level LoggingLevel `json:"level"`
}

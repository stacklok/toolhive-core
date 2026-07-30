// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package recovery

import "net/http"

// PanicHandler receives recovered panics for observability backends.
// Implementations must be safe for concurrent use and must not panic.
//
// The two methods exist because backends have different data-safety
// contracts:
//
//   - RecordError is for telemetry that ships to shared/external systems
//     (tracing spans, metrics). It receives a generic error whose message
//     never contains the panic value, so implementations can safely attach
//     it to spans or error records.
//   - ReportPanic is for error-tracking backends the operator explicitly
//     configured (e.g. Sentry Issues). It receives the raw recovered panic
//     value, which such backends need to group and triage the failure.
type PanicHandler interface {
	// RecordError records a sanitized error for the request's panic.
	// The error message is always generic ("panic recovered") and contains
	// no panic value.
	RecordError(r *http.Request, err error)

	// ReportPanic reports the raw recovered panic value for the request.
	ReportPanic(r *http.Request, panicValue any)
}

// PanicHandlerFunc adapts a single function to PanicHandler, calling it
// from both RecordError and ReportPanic. The function receives the panic
// value on ReportPanic and nil on RecordError. Prefer implementing
// PanicHandler directly when the two channels need different treatment.
type PanicHandlerFunc func(r *http.Request, panicValue any)

// RecordError calls f(r, nil).
func (f PanicHandlerFunc) RecordError(r *http.Request, _ error) { f(r, nil) }

// ReportPanic calls f(r, panicValue).
func (f PanicHandlerFunc) ReportPanic(r *http.Request, panicValue any) { f(r, panicValue) }

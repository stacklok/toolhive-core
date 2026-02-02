// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package httperr provides error types with HTTP status codes for API error handling.

This package allows errors to carry their intended HTTP response code through the
call stack, enabling centralized error handling in API handlers. The CodedError
type implements the standard error interface and supports error wrapping via
errors.Is() and errors.As().

# Basic Usage

Create errors with HTTP status codes:

	// Create a new error with a status code
	err := httperr.New("resource not found", http.StatusNotFound)

	// Wrap an existing error with a status code
	err := httperr.WithCode(err, http.StatusBadRequest)

# Extracting Status Codes

Extract the HTTP status code from an error chain:

	code := httperr.Code(err)
	// Returns the code if err contains a CodedError
	// Returns http.StatusInternalServerError (500) if no CodedError found
	// Returns http.StatusOK (200) if err is nil

# Error Wrapping

CodedError supports the standard Go error wrapping pattern:

	sentinel := errors.New("database connection failed")
	err := httperr.WithCode(sentinel, http.StatusServiceUnavailable)

	// errors.Is works through the wrapper
	if errors.Is(err, sentinel) {
		// handle specific error
	}

	// errors.As can extract the CodedError
	var coded *httperr.CodedError
	if errors.As(err, &coded) {
		log.Printf("HTTP %d: %s", coded.HTTPCode(), coded.Error())
	}

# HTTP Handler Example

Use in an HTTP handler for centralized error responses:

	func handleError(w http.ResponseWriter, err error) {
		code := httperr.Code(err)
		http.Error(w, err.Error(), code)
	}

	func myHandler(w http.ResponseWriter, r *http.Request) {
		result, err := doSomething()
		if err != nil {
			handleError(w, err)
			return
		}
		// ...
	}
*/
package httperr

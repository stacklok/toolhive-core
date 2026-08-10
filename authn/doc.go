// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package authn validates INBOUND JWT bearer tokens at a resource server.
//
// It performs NO OAuth flows and issues nothing: there is no token endpoint,
// no authorization-code exchange, and no signing of tokens. The package only
// verifies bearer tokens presented by clients against configured keys and
// trusted issuer/audience policy.
//
// Failures from Validate and ParseBearer are expressed as *Error (see
// errors.go), which carries a client-safe Code and Reason alongside a detail
// string intended for logging. NewValidator, by contrast, returns ordinary
// construction errors.
package authn

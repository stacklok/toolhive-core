// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package env provides an interface-based abstraction for environment variable
access, enabling dependency injection and testing isolation.

# Basic Usage

Use OSReader to read environment variables via the standard os package:

	reader := &env.OSReader{}
	value := reader.Getenv("MY_VAR")

# Testing

The Reader interface allows injecting a mock in tests to avoid relying on
real environment variables. A generated mock is available in the mocks
sub-package:

	ctrl := gomock.NewController(t)
	mock := mocks.NewMockReader(ctrl)
	mock.EXPECT().Getenv("MY_VAR").Return("test-value")

	result := myFunc(mock)

# Design

This package follows the interface-based dependency injection pattern used
throughout toolhive-core. Production code accepts an env.Reader, while tests
substitute the generated mock.
*/
package env

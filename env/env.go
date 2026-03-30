// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package env

//go:generate mockgen -copyright_file=../.github/license-header.txt -source=env.go -destination=mocks/mock_reader.go -package=mocks Reader

import "os"

// Reader defines an interface for environment variable access
type Reader interface {
	Getenv(key string) string
	LookupEnv(key string) (string, bool)
}

// OSReader implements Reader using the standard os package
type OSReader struct{}

// Getenv returns the value of the environment variable named by the key
func (*OSReader) Getenv(key string) string {
	return os.Getenv(key)
}

// LookupEnv returns the value of the environment variable named by the key
func (r *OSReader) LookupEnv(key string) (string, bool) {
	return os.LookupEnv(key)
}

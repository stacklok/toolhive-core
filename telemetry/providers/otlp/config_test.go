// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_ExportTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		timeout time.Duration
		want    time.Duration
	}{
		{name: "unset falls back to this package's default, not the SDK's 10s", want: 30 * time.Second},
		{name: "zero falls back to the default", timeout: 0, want: 30 * time.Second},
		{name: "negative falls back to the default", timeout: -time.Second, want: 30 * time.Second},
		{name: "explicit value is used as given", timeout: 90 * time.Second, want: 90 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := Config{ExportTimeout: tt.timeout}
			assert.Equal(t, tt.want, config.exportTimeout())
		})
	}
}

func TestConfig_IsGRPC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol string
		want     bool
	}{
		{name: "unset protocol is not gRPC (backward compat default)", protocol: "", want: false},
		{name: "explicit http/protobuf is not gRPC", protocol: ProtocolHTTPProtobuf, want: false},
		{name: "grpc is gRPC", protocol: ProtocolGRPC, want: true},
		{name: "unrecognized value is not gRPC", protocol: "unknown", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := Config{Protocol: tt.protocol}
			assert.Equal(t, tt.want, config.isGRPC())
		})
	}
}

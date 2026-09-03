// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

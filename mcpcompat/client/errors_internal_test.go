// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

func TestMapTransportError_Unauthorized(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("request failed: 401 Unauthorized"))

	// ToolHive branches on all of these for its OAuth/401 handling.
	assert.True(t, errors.Is(err, transport.ErrUnauthorized), "errors.Is ErrUnauthorized")
	assert.True(t, errors.Is(err, transport.ErrAuthorizationRequired), "errors.Is ErrAuthorizationRequired")

	var te *transport.Error
	assert.True(t, errors.As(err, &te), "errors.As *transport.Error")

	var are *transport.AuthorizationRequiredError
	assert.True(t, errors.As(err, &are), "errors.As *AuthorizationRequiredError")
}

func TestMapTransportError_SessionTerminated(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("server returned 404: session not found"))
	assert.True(t, errors.Is(err, transport.ErrSessionTerminated))
}

func TestMapTransportError_LegacySSE(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("405 method not allowed"))
	assert.True(t, errors.Is(err, transport.ErrLegacySSEServer))
}

func TestMapTransportError_Passthrough(t *testing.T) {
	t.Parallel()
	orig := errors.New("some unrelated failure")
	assert.Equal(t, orig, mapTransportError(orig))
}

func TestMapTransportError_Nil(t *testing.T) {
	t.Parallel()
	assert.NoError(t, mapTransportError(nil))
}

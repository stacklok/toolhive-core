// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestClientSessionRelease verifies that release clears every per-session
// reference a clientSession owns: the per-session go-sdk server (boundServer),
// the bound go-sdk session (goSession), the owner, the capability/protocol
// bookkeeping, and the tools/resources/resource-templates/prompts overlays.
// This is what lets a lingering reference to the clientSession (for example a
// list_changed sink a backend connector holds) stop pinning the per-session
// go-sdk server and its converted tool schemas after forgetSession.
func TestClientSessionRelease(t *testing.T) {
	t.Parallel()

	cs := newClientSession("sess-1")
	t.Cleanup(func() { cs.notifClose.Do(func() { close(cs.notifCh) }) })

	cs.boundServer.Store(gosdk.NewServer(&gosdk.Implementation{Name: "x", Version: "1"}, nil))
	cs.goSession.Store(&gosdk.ServerSession{})
	cs.owner.Store(NewMCPServer("x", "1"))
	cs.initializedOn.Store(&gosdk.ServerSession{})
	cs.negotiated.Store(&negotiatedProtocolVersion{version: "2025-06-18", on: &gosdk.ServerSession{}})

	cs.mu.Lock()
	cs.tools = map[string]ServerTool{"echo": {Tool: mcp.Tool{Name: "echo"}}}
	cs.resources = map[string]ServerResource{"file:///r": {Resource: mcp.Resource{URI: "file:///r"}}}
	cs.resourceTemplates = map[string]ServerResourceTemplate{
		"file:///{x}": {Template: mcp.ResourceTemplate{URITemplate: "file:///{x}"}},
	}
	cs.prompts = map[string]ServerPrompt{"p": {Prompt: mcp.Prompt{Name: "p"}}}
	cs.sdkToolNames = map[string]struct{}{"echo": {}}
	cs.mu.Unlock()

	cs.release()

	assert.Nil(t, cs.boundServer.Load())
	assert.Nil(t, cs.goSession.Load())
	assert.Nil(t, cs.owner.Load())
	assert.Nil(t, cs.initializedOn.Load())
	assert.Nil(t, cs.negotiated.Load())

	cs.mu.RLock()
	defer cs.mu.RUnlock()
	assert.Nil(t, cs.tools)
	assert.Nil(t, cs.resources)
	assert.Nil(t, cs.resourceTemplates)
	assert.Nil(t, cs.prompts)
	assert.Nil(t, cs.sdkToolNames)
}

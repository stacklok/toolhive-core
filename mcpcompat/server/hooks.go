// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// OnRegisterSessionHookFunc runs when a session registers.
type OnRegisterSessionHookFunc func(ctx context.Context, session ClientSession)

// OnBeforeListToolsFunc runs before a tools/list request is handled.
type OnBeforeListToolsFunc func(ctx context.Context, id any, message *mcp.ListToolsRequest)

// OnBeforeCallToolFunc runs before a tools/call request is handled.
type OnBeforeCallToolFunc func(ctx context.Context, id any, message *mcp.CallToolRequest)

// Hooks holds lifecycle callbacks. It mirrors the subset of mcp-go's
// server.Hooks that ToolHive registers.
type Hooks struct {
	registerSessionHooks []OnRegisterSessionHookFunc
	listToolsHooks       []OnBeforeListToolsFunc
	callToolHooks        []OnBeforeCallToolFunc
}

// AddOnRegisterSession registers a session-registration hook.
func (c *Hooks) AddOnRegisterSession(hook OnRegisterSessionHookFunc) {
	c.registerSessionHooks = append(c.registerSessionHooks, hook)
}

// AddBeforeListTools registers a before-tools/list hook.
func (c *Hooks) AddBeforeListTools(hook OnBeforeListToolsFunc) {
	c.listToolsHooks = append(c.listToolsHooks, hook)
}

// AddBeforeCallTool registers a before-tools/call hook.
func (c *Hooks) AddBeforeCallTool(hook OnBeforeCallToolFunc) {
	c.callToolHooks = append(c.callToolHooks, hook)
}

func (c *Hooks) registerSession(ctx context.Context, session ClientSession) {
	for _, h := range c.registerSessionHooks {
		h(ctx, session)
	}
}

func (c *Hooks) beforeCallTool(ctx context.Context, id any, message *mcp.CallToolRequest) {
	for _, h := range c.callToolHooks {
		h(ctx, id, message)
	}
}

func (c *Hooks) beforeListTools(ctx context.Context, id any, message *mcp.ListToolsRequest) {
	for _, h := range c.listToolsHooks {
		h(ctx, id, message)
	}
}

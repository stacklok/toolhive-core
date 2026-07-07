// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package mcp is a drop-in compatibility shim for github.com/mark3labs/mcp-go/mcp.
//
// It exists so that ToolHive and its sibling projects can migrate off mcp-go and
// onto the official Model Context Protocol Go SDK
// (github.com/modelcontextprotocol/go-sdk) by swapping imports rather than
// rewriting call sites: replace
//
//	github.com/mark3labs/mcp-go/mcp
//
// with
//
//	github.com/stacklok/toolhive-core/mcpcompat/mcp
//
// while keeping the existing import alias. The companion packages
// mcpcompat/server, mcpcompat/client and mcpcompat/client/transport reimplement
// mcp-go's protocol machinery on top of the official SDK; this package supplies
// the data types those APIs exchange.
//
// # Migration strategy
//
// The types and helpers below are currently re-exported from mcp-go via type
// aliases and value assignments. This guarantees byte-for-byte wire and source
// compatibility during the transition: the aliased symbols ARE mcp-go's, so
// existing struct-literal construction, field access and custom JSON marshaling
// behave identically.
//
// This file is the single chokepoint that still references mcp-go. The end goal
// is to remove the mcp-go dependency from the tree entirely. To get there, each
// alias here is replaced by a standalone definition (copied from the mcp-go
// source, same JSON tags and marshaling). Because consumers only ever see the
// symbols in this package, that swap is transparent to them. The wire-format
// golden tests in this package pin the exact JSON shape of every re-exported
// type and are what make the alias-to-standalone conversion safe.
//
// # Scope
//
// Only the subset of mcp-go's mcp package that ToolHive actually uses is
// re-exported. Unused surface (sampling, roots, completion, tasks, logging-level
// control, the fluent schema builder beyond WithDescription/WithString/Required,
// etc.) is intentionally omitted and can be added on demand.
//
// Stability: Alpha.
package mcp

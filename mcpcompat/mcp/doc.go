// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package mcp is a standalone reimplementation of the data types from
// mark3labs/mcp-go/mcp.
//
// It exists so that ToolHive and its sibling projects can migrate off mcp-go
// and onto the official Model Context Protocol Go SDK
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
// The types and helpers below are standalone definitions that preserve the
// mcp-go JSON wire format (same struct tags, same custom marshaling). The
// mcp-go dependency has been removed from the tree entirely. The wire-format
// golden tests in this package pin the exact JSON shape of every type and are
// what make future changes safe.
//
// # Scope
//
// Only the subset of mcp-go's mcp package that ToolHive actually uses is
// included. Unused surface (sampling, roots, completion, tasks, logging-level
// control, the fluent schema builder beyond WithDescription/WithString/Required,
// etc.) is intentionally omitted and can be added on demand.
//
// Stability: Alpha.
package mcp

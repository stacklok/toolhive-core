// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestAdaptSkillsMethod_EmptyListsEncodeAsArrays checks the wire form go-sdk
// sends for a handler with nothing to list: the extension defines skills and
// resources as arrays, so a nil slice must reach the wire as [] rather than
// null. A Go client decodes either, so only the encoded wire struct shows it.
func TestAdaptSkillsMethod_EmptyListsEncodeAsArrays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	list := adaptSkillsMethod[sdkListSkillsParams, *sdkListSkillsParams, sdkListSkillsResult](
		mcp.MethodSkillsList,
		func(context.Context, mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
			return &mcp.ListSkillsResult{}, nil
		})
	listRes, err := list(ctx, nil, &sdkListSkillsParams{})
	require.NoError(t, err)
	listWire, err := json.Marshal(listRes)
	require.NoError(t, err)
	assert.JSONEq(t, `{"skills":[]}`, string(listWire))

	dir := adaptSkillsMethod[sdkReadDirectoryParams, *sdkReadDirectoryParams, sdkReadDirectoryResult](
		mcp.MethodResourcesDirectoryRead,
		func(context.Context, mcp.ReadDirectoryRequest) (*mcp.ReadDirectoryResult, error) {
			return &mcp.ReadDirectoryResult{}, nil
		})
	dirRes, err := dir(ctx, nil, &sdkReadDirectoryParams{URI: "skill://empty"})
	require.NoError(t, err)
	dirWire, err := json.Marshal(dirRes)
	require.NoError(t, err)
	assert.JSONEq(t, `{"resources":[]}`, string(dirWire))
}

// TestAdaptSkillsMethod_NilResultAndPanicAreErrors checks that a handler
// returning (nil, nil), or panicking, fails the request rather than sending a
// zero-valued result or crashing.
func TestAdaptSkillsMethod_NilResultAndPanicAreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	nilResult := adaptSkillsMethod[sdkGetSkillParams, *sdkGetSkillParams, sdkGetSkillResult](
		mcp.MethodSkillsGet,
		func(context.Context, mcp.GetSkillRequest) (*mcp.GetSkillResult, error) { return nil, nil })
	_, err := nilResult(ctx, nil, &sdkGetSkillParams{URI: "skill://a/SKILL.md"})
	require.ErrorContains(t, err, "skills/get handler returned no result")

	panics := adaptSkillsMethod[sdkGetSkillParams, *sdkGetSkillParams, sdkGetSkillResult](
		mcp.MethodSkillsGet,
		func(context.Context, mcp.GetSkillRequest) (*mcp.GetSkillResult, error) { panic("boom") })
	_, err = panics(ctx, nil, &sdkGetSkillParams{URI: "skill://a/SKILL.md"})
	require.ErrorContains(t, err, "panic recovered in skills/get handler: boom")
}

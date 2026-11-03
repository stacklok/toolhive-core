// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// The go-sdk wire forms of the Skills extension's messages. go-sdk sends a
// custom method only with params and results that implement its sealed Params
// and Result interfaces, which only embedding ParamsBase/ResultBase achieves;
// the shim converts between these and the mcp-go-shaped types via JSON
// round-trips, as it does for every other method. They match the server
// package's forms.
type (
	sdkListSkillsParams struct {
		gosdk.ParamsBase
		Cursor string `json:"cursor,omitempty"`
	}
	sdkListSkillsResult struct {
		gosdk.ResultBase
		Skills     []mcp.Skill `json:"skills"`
		NextCursor string      `json:"nextCursor,omitempty"`
	}
	sdkGetSkillParams struct {
		gosdk.ParamsBase
		URI string `json:"uri"`
	}
	sdkGetSkillResult struct {
		gosdk.ResultBase
		Skill mcp.Skill `json:"skill"`
	}
	sdkReadDirectoryParams struct {
		gosdk.ParamsBase
		URI    string `json:"uri"`
		Cursor string `json:"cursor,omitempty"`
	}
	sdkReadDirectoryResult struct {
		gosdk.ResultBase
		Resources  []mcp.Resource `json:"resources"`
		NextCursor string         `json:"nextCursor,omitempty"`
	}
)

// ListSkills lists the skills the server serves (skills/list, from the Skills
// extension). mcp-go has no equivalent.
//
// Call it only on a server whose initialize result declares
// mcp.ExtensionSkills under Capabilities.Extensions: a go-sdk server that does
// not serve the method answers with HTTP 400 rather than a JSON-RPC
// method-not-found, so the error alone does not say the extension is absent.
func (c *Client) ListSkills(ctx context.Context, request mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
	return callSkillsMethod[
		sdkListSkillsParams, *sdkListSkillsParams, sdkListSkillsResult, *sdkListSkillsResult, mcp.ListSkillsResult,
	](
		ctx, c, mcp.MethodSkillsList, request.Params)
}

// GetSkill returns the entry for one skill by the URI of its SKILL.md
// (skills/get, from the Skills extension). mcp-go has no equivalent. A server
// answers a URI that names no skill it serves with JSON-RPC error -32602,
// returned as the go-sdk *jsonrpc.Error. See ListSkills for when to call it.
func (c *Client) GetSkill(ctx context.Context, request mcp.GetSkillRequest) (*mcp.GetSkillResult, error) {
	return callSkillsMethod[
		sdkGetSkillParams, *sdkGetSkillParams, sdkGetSkillResult, *sdkGetSkillResult, mcp.GetSkillResult,
	](
		ctx, c, mcp.MethodSkillsGet, request.Params)
}

// ReadDirectory lists the direct children of a directory resource
// (resources/directory/read, the Skills extension's optional method). mcp-go
// has no equivalent. A server answers a URI that does not exist, or is not a
// directory, with JSON-RPC error -32602, returned as the go-sdk
// *jsonrpc.Error.
//
// Call it only on a server whose Skills extension settings declare
// mcp.SkillsSettingDirectoryRead as true: the extension forbids calling it
// otherwise.
func (c *Client) ReadDirectory(
	ctx context.Context, request mcp.ReadDirectoryRequest,
) (*mcp.ReadDirectoryResult, error) {
	return callSkillsMethod[
		sdkReadDirectoryParams, *sdkReadDirectoryParams,
		sdkReadDirectoryResult, *sdkReadDirectoryResult,
		mcp.ReadDirectoryResult,
	](
		ctx, c, mcp.MethodResourcesDirectoryRead, request.Params)
}

// callSkillsMethod sends one of the extension's methods with params (the
// mcp-go-shaped request params) and returns the mcp-go-shaped result MRes,
// converting through the wire forms P (params) and R (result). It takes the resume path when the
// client resumed a session without Initialize, as the other methods do.
func callSkillsMethod[PT any, P interface {
	*PT
	gosdk.Params
}, RT any, R interface {
	*RT
	gosdk.Result
}, MRes any](
	ctx context.Context, c *Client, method mcp.MCPMethod, params any,
) (*MRes, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := new(MRes)
		return out, c.resumeCall(ctx, string(method), params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	wire := P(new(PT))
	if err := jsonConvert(params, wire); err != nil {
		return nil, fmt.Errorf("converting %s request: %w", method, err)
	}
	res, err := gosdk.CallCustomMethod[P, R](ctx, s, string(method), wire)
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[MRes](res)
}

// registerSkillsMethods registers the extension's methods for sending on gc,
// which go-sdk requires before CallCustomMethod. Initialize calls it on every
// client it builds, so the methods work on any initialized session.
func registerSkillsMethods(gc *gosdk.Client) error {
	register := []func() error{
		func() error {
			return gosdk.AddSendingCustomMethod[*sdkListSkillsParams, *sdkListSkillsResult](
				gc, string(mcp.MethodSkillsList))
		},
		func() error {
			return gosdk.AddSendingCustomMethod[*sdkGetSkillParams, *sdkGetSkillResult](
				gc, string(mcp.MethodSkillsGet))
		},
		func() error {
			return gosdk.AddSendingCustomMethod[*sdkReadDirectoryParams, *sdkReadDirectoryResult](
				gc, string(mcp.MethodResourcesDirectoryRead))
		},
	}
	for _, r := range register {
		if err := r(); err != nil {
			return fmt.Errorf("registering skills extension methods: %w", err)
		}
	}
	return nil
}

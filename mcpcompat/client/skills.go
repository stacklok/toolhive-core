// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// The go-sdk wire forms of the skills messages. go-sdk sends a custom method
// only with params and results that implement its sealed Params and Result
// interfaces, which only embedding ParamsBase/ResultBase achieves; the shim
// converts between these and the mcp-go-shaped types via JSON round-trips, as
// it does for every other method. They match the server package's forms.
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
)

// ListSkills lists the skills the server serves (skills/list, from the Skills
// extension). mcp-go has no equivalent.
//
// Call it only on a server whose initialize result declares
// mcp.ExtensionSkills under Capabilities.Extensions: a go-sdk server that does
// not serve the method answers with HTTP 400 rather than a JSON-RPC
// method-not-found, so the error alone does not say the extension is absent.
func (c *Client) ListSkills(ctx context.Context, request mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.ListSkillsResult{}
		return out, c.resumeCall(ctx, string(mcp.MethodSkillsList), request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	params := &sdkListSkillsParams{}
	if err := jsonConvert(request.Params, params); err != nil {
		return nil, fmt.Errorf("converting skills/list request: %w", err)
	}
	res, err := gosdk.CallCustomMethod[*sdkListSkillsParams, *sdkListSkillsResult](
		ctx, s, string(mcp.MethodSkillsList), params)
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.ListSkillsResult](res)
}

// GetSkill returns the entry for one skill by the URI of its SKILL.md
// (skills/get, from the Skills extension). mcp-go has no equivalent. A server
// answers a URI that names no skill it serves with JSON-RPC error -32602,
// returned as the go-sdk *jsonrpc.Error. See ListSkills for when to call it.
func (c *Client) GetSkill(ctx context.Context, request mcp.GetSkillRequest) (*mcp.GetSkillResult, error) {
	ctx = withErrCapture(ctx)
	if c.isResume() {
		out := &mcp.GetSkillResult{}
		return out, c.resumeCall(ctx, string(mcp.MethodSkillsGet), request.Params, out)
	}
	s, err := c.sessionFor()
	if err != nil {
		return nil, err
	}
	params := &sdkGetSkillParams{}
	if err := jsonConvert(request.Params, params); err != nil {
		return nil, fmt.Errorf("converting skills/get request: %w", err)
	}
	res, err := gosdk.CallCustomMethod[*sdkGetSkillParams, *sdkGetSkillResult](
		ctx, s, string(mcp.MethodSkillsGet), params)
	if err != nil {
		return nil, mapCallError(ctx, err)
	}
	return convertResult[mcp.GetSkillResult](res)
}

// registerSkillsMethods registers the skills methods for sending on gc, which
// go-sdk requires before CallCustomMethod. Initialize calls it on every client
// it builds, so ListSkills and GetSkill work on any initialized session.
func registerSkillsMethods(gc *gosdk.Client) error {
	if err := gosdk.AddSendingCustomMethod[*sdkListSkillsParams, *sdkListSkillsResult](
		gc, string(mcp.MethodSkillsList)); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsList, err)
	}
	if err := gosdk.AddSendingCustomMethod[*sdkGetSkillParams, *sdkGetSkillResult](
		gc, string(mcp.MethodSkillsGet)); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsGet, err)
	}
	return nil
}

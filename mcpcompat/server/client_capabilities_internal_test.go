// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

func TestFromGoSDKClientCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   *gosdk.ClientCapabilities
		want mcp.ClientCapabilities
	}{
		{
			name: "nil capabilities",
			in:   nil,
			want: mcp.ClientCapabilities{},
		},
		{
			name: "empty capabilities",
			in:   &gosdk.ClientCapabilities{},
			want: mcp.ClientCapabilities{},
		},
		{
			// The deprecated non-pointer Roots field is populated but RootsV2
			// is nil: roots were not declared and must not be reported.
			name: "legacy roots field alone is not presence",
			in: &gosdk.ClientCapabilities{
				Roots: struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{ListChanged: true},
			},
			want: mcp.ClientCapabilities{},
		},
		{
			name: "roots via RootsV2",
			in:   &gosdk.ClientCapabilities{RootsV2: &gosdk.RootCapabilities{ListChanged: true}},
			want: mcp.ClientCapabilities{Roots: &struct {
				ListChanged bool `json:"listChanged,omitempty"`
			}{ListChanged: true}},
		},
		{
			name: "sampling with context and tools",
			in: &gosdk.ClientCapabilities{Sampling: &gosdk.SamplingCapabilities{
				Context: &gosdk.SamplingContextCapabilities{},
				Tools:   &gosdk.SamplingToolsCapabilities{},
			}},
			want: mcp.ClientCapabilities{Sampling: &mcp.SamplingCapability{
				Context: &struct{}{},
				Tools:   &struct{}{},
			}},
		},
		{
			name: "empty elicitation",
			in:   &gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{}},
			want: mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapability{}},
		},
		{
			name: "form and url elicitation",
			in: &gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{
				Form: &gosdk.FormElicitationCapabilities{},
				URL:  &gosdk.URLElicitationCapabilities{},
			}},
			want: mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapability{
				Form: &struct{}{},
				URL:  &struct{}{},
			}},
		},
		{
			name: "experimental and extensions",
			in: &gosdk.ClientCapabilities{
				Experimental: map[string]any{"x": map[string]any{}},
				Extensions:   map[string]any{"io.example/ext": map[string]any{"k": "v"}},
			},
			want: mcp.ClientCapabilities{
				Experimental: map[string]any{"x": map[string]any{}},
				Extensions:   map[string]any{"io.example/ext": map[string]any{"k": "v"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, fromGoSDKClientCapabilities(tc.in))
		})
	}
}

// TestDeclaredClientCapabilities_UnknownStates covers the known=false paths
// that do not need a live transport: no bound go-sdk session, and a bound
// session that differs from the one initialize was observed on.
func TestDeclaredClientCapabilities_UnknownStates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		bound  *gosdk.ServerSession
		initOn *gosdk.ServerSession
	}{
		{name: "no bound session"},
		{name: "initialize observed on a different session", bound: &gosdk.ServerSession{}, initOn: &gosdk.ServerSession{}},
		{name: "bound session never observed initialize", bound: &gosdk.ServerSession{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := newClientSession("sid")
			t.Cleanup(func() { close(cs.notifCh) })
			if tc.bound != nil {
				cs.goSession.Store(tc.bound)
			}
			if tc.initOn != nil {
				cs.initializedOn.Store(tc.initOn)
			}
			caps, known := cs.DeclaredClientCapabilities()
			assert.False(t, known)
			assert.Equal(t, mcp.ClientCapabilities{}, caps)
		})
	}
}

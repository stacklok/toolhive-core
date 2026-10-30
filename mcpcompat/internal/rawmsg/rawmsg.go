// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package rawmsg provides go-sdk Params and Result implementations that carry
// an undecoded JSON object. The mcpcompat server and client use them to serve
// and send custom (non-standard) JSON-RPC methods, such as an extension's
// methods, whose shapes the shim does not model and must pass through
// byte-for-byte.
//
// go-sdk reads and writes the _meta member of every params and result value
// (for example, it stamps _meta.serverInfo on results and _meta client info on
// 2026-07-28 requests), so each type keeps _meta decoded in its embedded Meta
// and merges it back into the object when marshaled. Every other member is
// preserved exactly as received.
package rawmsg

import (
	"bytes"
	"encoding/json"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// metaKey is the reserved member that carries MCP metadata.
const metaKey = "_meta"

// Params is a go-sdk Params value holding an undecoded JSON object.
type Params struct {
	gosdk.ParamsBase
	raw json.RawMessage
}

// NewParams returns Params carrying raw, which must be a JSON object, or empty
// for no params. Any _meta member in raw is decoded into the embedded Meta.
func NewParams(raw json.RawMessage) (*Params, error) {
	p := &Params{}
	if len(raw) == 0 {
		return p, nil
	}
	if err := p.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return p, nil
}

// Raw returns the params as a JSON object, with the current Meta merged in.
func (p *Params) Raw() (json.RawMessage, error) {
	return merge(p.raw, p.Meta)
}

// UnmarshalJSON records data and decodes its _meta member.
func (p *Params) UnmarshalJSON(data []byte) error {
	meta, err := decode(data)
	if err != nil {
		return err
	}
	p.raw = bytes.Clone(data)
	p.Meta = meta
	return nil
}

// MarshalJSON returns the recorded object with the current Meta merged in.
func (p *Params) MarshalJSON() ([]byte, error) {
	return p.Raw()
}

// Result is a go-sdk Result value holding an undecoded JSON object.
type Result struct {
	gosdk.ResultBase
	raw json.RawMessage
}

// NewResult returns a Result carrying raw, which must be a JSON object. Any
// _meta member in raw is decoded into the embedded Meta. An empty raw is
// treated as the empty object, since a JSON-RPC result cannot be absent.
func NewResult(raw json.RawMessage) (*Result, error) {
	r := &Result{}
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := r.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	return r, nil
}

// Raw returns the result as a JSON object, with the current Meta merged in.
func (r *Result) Raw() (json.RawMessage, error) {
	return merge(r.raw, r.Meta)
}

// UnmarshalJSON records data and decodes its _meta member.
func (r *Result) UnmarshalJSON(data []byte) error {
	meta, err := decode(data)
	if err != nil {
		return err
	}
	r.raw = bytes.Clone(data)
	r.Meta = meta
	return nil
}

// MarshalJSON returns the recorded object with the current Meta merged in.
func (r *Result) MarshalJSON() ([]byte, error) {
	return r.Raw()
}

// decode checks that data is a JSON object and returns its _meta member, or
// nil when it has none.
func decode(data []byte) (gosdk.Meta, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return nil, fmt.Errorf("decoding JSON object: %w", err)
	}
	if members == nil {
		return nil, fmt.Errorf("decoding JSON object: got null")
	}
	rawMeta, ok := members[metaKey]
	if !ok {
		return nil, nil
	}
	var meta gosdk.Meta
	if err := json.Unmarshal(rawMeta, &meta); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", metaKey, err)
	}
	return meta, nil
}

// merge returns raw with its _meta member replaced by meta, or removed when
// meta is empty. raw is not modified. An empty raw stands for the empty object.
func merge(raw json.RawMessage, meta gosdk.Meta) (json.RawMessage, error) {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	members := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("decoding JSON object: %w", err)
	}
	_, hadMeta := members[metaKey]
	if len(meta) == 0 {
		if !hadMeta {
			return bytes.Clone(raw), nil
		}
		delete(members, metaKey)
	} else {
		encoded, err := json.Marshal(meta)
		if err != nil {
			return nil, fmt.Errorf("encoding %s: %w", metaKey, err)
		}
		members[metaKey] = encoded
	}
	out, err := json.Marshal(members)
	if err != nil {
		return nil, fmt.Errorf("encoding JSON object: %w", err)
	}
	return out, nil
}

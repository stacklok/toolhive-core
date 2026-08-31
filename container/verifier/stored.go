// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// StoredBundleMediaType identifies the JSON envelope this package persists
// for a cosign simple-signing signature.
//
// A Sigstore bundle alone cannot express what a simple-signing signature
// binds to. The signature covers the simple-signing payload blob, and it is
// the payload — not the bundle — that names the artifact, via
// critical.image.docker-manifest-digest. The bundle protobuf has nowhere to
// put those payload bytes: a MessageSignature carries only a digest and a
// signature. So a bundle stored on its own is verifiable but unbindable —
// it proves someone signed *something*, with no way left to check what.
//
// The envelope closes that gap by persisting the payload next to the bundle:
//
//	{
//	  "mediaType": "application/vnd.toolhive.signature-bundle.v1+json",
//	  "bundle": { ...canonical Sigstore bundle JSON... },
//	  "simpleSigningPayload": "<base64 of the simple-signing payload>"
//	}
//
// Bundles that bind to the artifact structurally — attestation (referrer)
// bundles, whose in-toto subject is the artifact digest — need no payload and
// are persisted as bare Sigstore bundle JSON, unchanged. DecodeStoredBundle
// accepts both shapes, so callers hold one opaque blob either way.
const StoredBundleMediaType = "application/vnd.toolhive.signature-bundle.v1+json"

// storedBundleEnvelope is the wire shape of StoredBundleMediaType.
type storedBundleEnvelope struct {
	MediaType string `json:"mediaType"`
	// Bundle is the canonical Sigstore bundle JSON, embedded verbatim so
	// that a stored envelope can be unwrapped into something any
	// Sigstore-aware tool understands.
	Bundle json.RawMessage `json:"bundle"`
	// SimpleSigningPayload is the exact payload bytes the signature covers.
	// Exact matters: the signature is checked against their digest, so a
	// re-serialized or reordered payload would fail verification.
	SimpleSigningPayload []byte `json:"simpleSigningPayload"`
}

// EncodeStoredBundle returns the durable form of a Sigstore bundle: the form
// VerifyBundleOffline and VerifyBundleOfflineWithKey accept, and the form
// [Bundle.Raw] carries.
//
// bundleJSON is the canonical Sigstore bundle JSON.
// simpleSigningPayload is the cosign simple-signing payload the bundle's
// signature covers, or nil for a bundle that binds to the artifact without
// one (an attestation bundle). With no payload the bundle JSON is returned
// unchanged; with one, it is wrapped in the StoredBundleMediaType envelope.
func EncodeStoredBundle(bundleJSON, simpleSigningPayload []byte) ([]byte, error) {
	if len(simpleSigningPayload) == 0 {
		return bundleJSON, nil
	}
	if !json.Valid(bundleJSON) {
		return nil, errors.New("bundle is not valid JSON")
	}
	raw, err := json.Marshal(storedBundleEnvelope{
		MediaType:            StoredBundleMediaType,
		Bundle:               bundleJSON,
		SimpleSigningPayload: simpleSigningPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("serializing stored bundle: %w", err)
	}
	return raw, nil
}

// DecodeStoredBundle parses the durable form produced by EncodeStoredBundle
// (equivalently, [Bundle.Raw]) and binds it to artifactDigest, given as
// "<algorithm>:<hex>".
//
// artifactDigest is the ARTIFACT's own manifest digest — the value a caller
// naturally has from a lock file, a registry entry, or a `remote.Get`. It is
// never the digest of a simple-signing payload; the returned Bundle carries
// the payload itself when one is needed, so callers never handle payload
// digests.
//
// Both persisted shapes are accepted: the StoredBundleMediaType envelope,
// and bare Sigstore bundle JSON.
func DecodeStoredBundle(raw []byte, artifactDigest string) (Bundle, error) {
	digestAlgo, digestHex, err := splitArtifactDigest(artifactDigest)
	if err != nil {
		return Bundle{}, err
	}

	parsed, payload, err := decodeStoredBundleBytes(raw)
	if err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Parsed:               parsed,
		Raw:                  raw,
		DigestAlgo:           digestAlgo,
		DigestHex:            digestHex,
		SimpleSigningPayload: payload,
	}, nil
}

// decodeStoredBundleBytes splits a persisted bundle into its parsed Sigstore
// bundle and its simple-signing payload (nil when the shape carries none).
//
// The two shapes are told apart by "mediaType": a Sigstore bundle's own
// mediaType is one of the application/vnd.dev.sigstore.bundle values, so an
// exact match on StoredBundleMediaType cannot mistake one for the other.
func decodeStoredBundleBytes(raw []byte) (*bundle.Bundle, []byte, error) {
	var probe struct {
		MediaType string `json:"mediaType"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && probe.MediaType == StoredBundleMediaType {
		var env storedBundleEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, nil, fmt.Errorf("parsing stored bundle envelope: %w", err)
		}
		if len(env.SimpleSigningPayload) == 0 {
			return nil, nil, errors.New("parsing stored bundle envelope: no simple-signing payload")
		}
		parsed := &bundle.Bundle{}
		if err := parsed.UnmarshalJSON(env.Bundle); err != nil {
			return nil, nil, fmt.Errorf("parsing stored bundle: %w", err)
		}
		return parsed, env.SimpleSigningPayload, nil
	}

	parsed := &bundle.Bundle{}
	if err := parsed.UnmarshalJSON(raw); err != nil {
		return nil, nil, fmt.Errorf("parsing stored bundle: %w", err)
	}
	return parsed, nil, nil
}

// splitArtifactDigest splits an "<algorithm>:<hex>" digest string.
func splitArtifactDigest(artifactDigest string) (algo, hexDigest string, err error) {
	algo, hexDigest, ok := strings.Cut(artifactDigest, ":")
	if !ok || algo == "" || hexDigest == "" {
		return "", "", fmt.Errorf("artifact digest %q is not in <algorithm>:<hex> form", artifactDigest)
	}
	return algo, hexDigest, nil
}

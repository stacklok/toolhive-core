// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import (
	artifact "github.com/stacklok/toolhive-core/oci/artifact"
)

// Test-only forwarders for unexported artifact primitives that the existing
// oci/skills test suite (registry_test.go, gzip_test.go) references directly.
// Keeping these as test aliases lets the regression-gate tests stay unchanged
// after the primitives were moved into the oci/artifact package.

// gzipOSUnknown mirrors the gzip "unknown" OS header value used in tests.
const gzipOSUnknown = 255

// maxIndexManifests mirrors the artifact cap on manifests in an image index.
const maxIndexManifests = 32

// maxManifestLayers mirrors the artifact cap on layers in a manifest.
const maxManifestLayers = 64

// newValidatingTarget forwards to artifact.NewValidatingTarget.
var newValidatingTarget = artifact.NewValidatingTarget

// validateManifestCounts forwards to artifact.ValidateManifestCounts.
var validateManifestCounts = artifact.ValidateManifestCounts

// isManifestMediaType forwards to artifact.IsManifestMediaType.
var isManifestMediaType = artifact.IsManifestMediaType

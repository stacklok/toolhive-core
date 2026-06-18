// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package artifact provides artifact-agnostic OCI primitives shared by the
ToolHive ecosystem: reproducible tar archive creation and extraction,
reproducible gzip compression, OCI platform helpers, and pull-hardening
(size/count/digest validation) for registry operations.

These primitives are independent of any particular artifact type (skills,
plugins, etc.). Artifact-specific media types, labels, and annotations live in
the packages that define those artifacts (for example oci/skills).

# Reproducible Archives

CreateTar and Compress produce byte-stable output for identical input, which is
what makes artifact digests deterministic:

	data, err := artifact.CompressTar(files, artifact.DefaultTarOptions(), artifact.DefaultGzipOptions())

# Platform Helpers

PlatformString and ParsePlatform convert between OCI platform values and their
"os/arch" or "os/arch/variant" string form.

# Pull Hardening

ValidatingTarget wraps an oras.Target and enforces size and structure limits on
pushed content, defending against OOM and resource exhaustion from malicious
registries during pull operations.

# Stability

This package is Alpha. Breaking changes are possible between minor versions.
*/
package artifact

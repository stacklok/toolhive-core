// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images provides container image registry helpers for the ToolHive
// ecosystem: credential keychains for go-containerregistry and related
// image-reference utilities.
//
// The keychains resolve registry credentials from environment variables
// (per-registry or generic) before falling back to the default Docker
// config keychain, so headless environments (CI, Kubernetes pods) can
// authenticate without a Docker config file.
//
// This package is Alpha stability. The API may change significantly before
// reaching stable status in v1.0.0.
package images

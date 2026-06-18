// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

import "errors"

// Sentinel errors returned (wrapped) by the packager so callers can classify
// failures with errors.Is instead of matching error message strings. The
// underlying error message is preserved at each call site via fmt.Errorf
// with %w; only the classification is added.
var (
	// ErrInvalidPluginDir indicates the plugin directory is missing, not a
	// directory, or otherwise unsafe to read (e.g. contains path traversal).
	ErrInvalidPluginDir = errors.New("invalid plugin directory")

	// ErrPluginManifestMissing indicates .claude-plugin/plugin.json is not
	// present in the plugin directory.
	ErrPluginManifestMissing = errors.New(".claude-plugin/plugin.json missing")

	// ErrInvalidPluginManifest indicates the plugin manifest is malformed,
	// oversized, or missing required fields such as the plugin name.
	ErrInvalidPluginManifest = errors.New("invalid plugin manifest")

	// ErrTooManyFiles indicates the plugin directory exceeds the maximum
	// allowed number of files.
	ErrTooManyFiles = errors.New("too many files in plugin directory")

	// ErrPluginTooLarge indicates the plugin directory exceeds the maximum
	// allowed total size.
	ErrPluginTooLarge = errors.New("plugin directory too large")

	// ErrInvalidPluginFile indicates a per-file issue inside the plugin
	// directory: a symlink, a non-regular file, or an unreadable entry.
	ErrInvalidPluginFile = errors.New("invalid plugin file")
)

// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sink builds a pluggable io.Writer for audit event delivery,
// fanning a single JSON audit line out to any combination of stdout and an
// HTTP webhook.
//
// A component that constructs its own audit *slog.Logger builds it on top of
// the io.WriteCloser this package returns instead of a hardcoded os.Stdout.
// Every configured sink receives every write: a failing sink never prevents
// delivery to the others, and an empty configuration yields stdout only.
package sink

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"io"
	"log/slog"
	"os"
)

// NewAuditLogger creates a new structured audit logger that writes to the
// specified writer. A nil writer defaults to os.Stdout.
//
// The logger emits JSON at LevelAudit with the level rendered as the string
// "AUDIT" for compatibility with log aggregation systems (Loki,
// Elasticsearch, etc.) that expect standard level names — without the
// rewrite, audit events would appear as "INFO+2" and break level-based
// filtering.
func NewAuditLogger(w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}

	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: LevelAudit,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.LevelKey {
				if level, ok := a.Value.Any().(slog.Level); ok && level == LevelAudit {
					a.Value = slog.StringValue("AUDIT")
				}
			}
			return a
		},
	})

	return slog.New(handler)
}

// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuditLogger_EmitsAuditLevelString(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.Log(t.Context(), LevelAudit, "test audit event", slog.String("key", "value"))

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	assert.Equal(t, "AUDIT", record["level"], "level must render as AUDIT, not INFO+2")
	assert.Equal(t, "test audit event", record["msg"])
	assert.Equal(t, "value", record["key"])
}

func TestNewAuditLogger_SuppressesLowerLevels(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewAuditLogger(&buf)

	logger.Info("should not appear")
	assert.Empty(t, buf.String(), "INFO (0) is below LevelAudit (2) and must be suppressed")
}

func TestNewAuditLogger_NilWriterDefaultsToStdout(t *testing.T) {
	t.Parallel()

	// Must not panic; we can't easily capture os.Stdout here, just verify construction.
	logger := NewAuditLogger(nil)
	require.NotNil(t, logger)
	assert.True(t, logger.Enabled(t.Context(), LevelAudit))
}

func TestEventTypeConstants(t *testing.T) {
	t.Parallel()

	// Pin the wire values: these strings land in log aggregation queries and
	// dashboards, so renaming one is a breaking change.
	want := map[string]string{
		"EventTypeMCPInitialize":         EventTypeMCPInitialize,
		"EventTypeMCPToolCall":           EventTypeMCPToolCall,
		"EventTypeMCPToolsList":          EventTypeMCPToolsList,
		"EventTypeMCPResourceRead":       EventTypeMCPResourceRead,
		"EventTypeMCPResourcesList":      EventTypeMCPResourcesList,
		"EventTypeMCPPromptGet":          EventTypeMCPPromptGet,
		"EventTypeMCPPromptsList":        EventTypeMCPPromptsList,
		"EventTypeMCPNotification":       EventTypeMCPNotification,
		"EventTypeMCPPing":               EventTypeMCPPing,
		"EventTypeMCPLogging":            EventTypeMCPLogging,
		"EventTypeMCPCompletion":         EventTypeMCPCompletion,
		"EventTypeMCPRootsListChanged":   EventTypeMCPRootsListChanged,
		"EventTypeSSEConnection":         EventTypeSSEConnection,
		"EventTypeWorkflowStarted":       EventTypeWorkflowStarted,
		"EventTypeWorkflowCompleted":     EventTypeWorkflowCompleted,
		"EventTypeWorkflowFailed":        EventTypeWorkflowFailed,
		"EventTypeWorkflowTimedOut":      EventTypeWorkflowTimedOut,
		"EventTypeWorkflowStepStarted":   EventTypeWorkflowStepStarted,
		"EventTypeWorkflowStepCompleted": EventTypeWorkflowStepCompleted,
		"EventTypeWorkflowStepFailed":    EventTypeWorkflowStepFailed,
		"EventTypeWorkflowStepSkipped":   EventTypeWorkflowStepSkipped,
		"EventTypeMCPRequest":            EventTypeMCPRequest,
		"EventTypeHTTPRequest":           EventTypeHTTPRequest,
	}
	for name, got := range want {
		assert.NotEmpty(t, got, "%s must not be empty", name)
	}

	// Spot-check the exact wire format for the most-queried events.
	assert.Equal(t, "mcp_tool_call", EventTypeMCPToolCall)
	assert.Equal(t, "mcp_initialize", EventTypeMCPInitialize)
	assert.Equal(t, "vmcp_workflow_started", EventTypeWorkflowStarted)
	assert.Equal(t, "vmcp_workflow_step_failed", EventTypeWorkflowStepFailed)
	assert.Equal(t, "http_request", EventTypeHTTPRequest)
}

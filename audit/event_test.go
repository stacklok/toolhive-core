// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	subjKeyUser      = "user"
	subjKeyUserID    = "user_id"
	subjKeyUserAgent = "user_agent"
	targetKeyName    = "name"
	targetKeyEndpt   = "endpoint"
	targetKeyType    = "type"
	targetTypeTool   = "tool"
)

func TestNewAuditEvent(t *testing.T) {
	t.Parallel()
	source := EventSource{
		Type:  SourceTypeNetwork,
		Value: "192.168.1.100",
		Extra: map[string]any{subjKeyUserAgent: "test-agent"},
	}
	subjects := map[string]string{
		subjKeyUser:   "testuser",
		subjKeyUserID: "user123",
	}

	event := NewAuditEvent("test_event", source, OutcomeSuccess, subjects, "test-component")

	assert.NotEmpty(t, event.Metadata.AuditID)
	assert.Equal(t, "test_event", event.Type)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, source, event.Source)
	assert.Equal(t, subjects, event.Subjects)
	assert.Equal(t, "test-component", event.Component)
	assert.WithinDuration(t, time.Now().UTC(), event.LoggedAt, time.Second)
}

func TestNewAuditEventWithID(t *testing.T) {
	t.Parallel()
	auditID := "custom-audit-id"
	source := EventSource{Type: SourceTypeLocal, Value: "localhost"}
	subjects := map[string]string{subjKeyUser: "admin"}

	event := NewAuditEventWithID(auditID, "admin_action", source, OutcomeSuccess, subjects, "admin-panel")

	assert.Equal(t, auditID, event.Metadata.AuditID)
	assert.Equal(t, "admin_action", event.Type)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, source, event.Source)
	assert.Equal(t, subjects, event.Subjects)
	assert.Equal(t, "admin-panel", event.Component)
}

func TestAuditEventWithTarget(t *testing.T) {
	t.Parallel()
	event := NewAuditEvent("test", EventSource{}, OutcomeSuccess, map[string]string{}, "test")
	target := map[string]string{
		targetKeyType:  targetTypeTool,
		targetKeyName:  "test-tool",
		targetKeyEndpt: "/api/tools/test",
	}

	result := event.WithTarget(target)

	assert.Equal(t, event, result)
	assert.Equal(t, target, event.Target)
}

func TestAuditEventWithData(t *testing.T) {
	t.Parallel()
	event := NewAuditEvent("test", EventSource{}, OutcomeSuccess, map[string]string{}, "test")
	testData := map[string]any{"key": "value", "number": 42}
	dataBytes, err := json.Marshal(testData)
	require.NoError(t, err)
	rawMsg := json.RawMessage(dataBytes)

	result := event.WithData(&rawMsg)

	assert.Equal(t, event, result)
	assert.Equal(t, &rawMsg, event.Data)
}

func TestAuditEventWithDataFromString(t *testing.T) {
	t.Parallel()
	event := NewAuditEvent("test", EventSource{}, OutcomeSuccess, map[string]string{}, "test")
	jsonString := `{"message": "test data", "count": 5}`

	result := event.WithDataFromString(jsonString)

	assert.Equal(t, event, result)
	require.NotNil(t, event.Data)

	var data map[string]any
	err := json.Unmarshal(*event.Data, &data)
	require.NoError(t, err)
	assert.Equal(t, "test data", data["message"])
	assert.Equal(t, float64(5), data["count"])
}

func TestAuditEventJSONSerialization(t *testing.T) {
	t.Parallel()
	source := EventSource{
		Type:  SourceTypeNetwork,
		Value: "10.0.0.1",
		Extra: map[string]any{
			subjKeyUserAgent: "Mozilla/5.0",
			"request_id":     "req-123",
		},
	}
	subjects := map[string]string{
		subjKeyUser:      "john.doe",
		subjKeyUserID:    "user-456",
		"client_name":    "test-client",
		"client_version": "1.0.0",
	}
	target := map[string]string{
		targetKeyType:  targetTypeTool,
		targetKeyName:  "calculator",
		"method":       "POST",
		targetKeyEndpt: "/api/tools/calculator",
	}

	event := NewAuditEvent("mcp_tool_call", source, OutcomeSuccess, subjects, "calculator-service")
	event.WithTarget(target)
	event.Metadata.Extra = map[string]any{
		"duration_ms":         150,
		"transport":           "sse",
		"mcp_version":         "2025-03-26",
		"response_size_bytes": 1024,
	}

	jsonData, err := json.Marshal(event)
	require.NoError(t, err)

	var deserialized AuditEvent
	err = json.Unmarshal(jsonData, &deserialized)
	require.NoError(t, err)

	assert.Equal(t, event.Metadata.AuditID, deserialized.Metadata.AuditID)
	assert.Equal(t, event.Type, deserialized.Type)
	assert.Equal(t, event.Outcome, deserialized.Outcome)
	assert.Equal(t, event.Source.Type, deserialized.Source.Type)
	assert.Equal(t, event.Source.Value, deserialized.Source.Value)
	assert.Equal(t, event.Subjects, deserialized.Subjects)
	assert.Equal(t, event.Component, deserialized.Component)
	assert.Equal(t, event.Target, deserialized.Target)
	assert.Equal(t, float64(150), deserialized.Metadata.Extra["duration_ms"])
	assert.Equal(t, "sse", deserialized.Metadata.Extra["transport"])
	assert.Equal(t, "2025-03-26", deserialized.Metadata.Extra["mcp_version"])
	assert.Equal(t, float64(1024), deserialized.Metadata.Extra["response_size_bytes"])
}

func TestConstants(t *testing.T) {
	t.Parallel()

	t.Run("source types", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "network", SourceTypeNetwork)
		assert.Equal(t, "local", SourceTypeLocal)
	})

	t.Run("outcomes", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "success", OutcomeSuccess)
		assert.Equal(t, "failure", OutcomeFailure)
		assert.Equal(t, "error", OutcomeError)
		assert.Equal(t, "denied", OutcomeDenied)
	})

	t.Run("component", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "toolhive-api", ComponentToolHive)
	})
}

func TestEventMetadataExtra(t *testing.T) {
	t.Parallel()
	event := NewAuditEvent("test", EventSource{}, OutcomeSuccess, map[string]string{}, "test")

	assert.Nil(t, event.Metadata.Extra)

	event.Metadata.Extra = map[string]any{
		"custom_field": "custom_value",
		"number_field": 42,
	}

	assert.Equal(t, "custom_value", event.Metadata.Extra["custom_field"])
	assert.Equal(t, 42, event.Metadata.Extra["number_field"])
}

func TestEventSourceExtra(t *testing.T) {
	t.Parallel()
	source := EventSource{
		Type:  SourceTypeNetwork,
		Value: "192.168.1.1",
		Extra: map[string]any{
			"port":     8080,
			"protocol": "https",
		},
	}

	event := NewAuditEvent("test", source, OutcomeSuccess, map[string]string{}, "test")

	assert.Equal(t, 8080, event.Source.Extra["port"])
	assert.Equal(t, "https", event.Source.Extra["protocol"])
}

func TestAuditEventLogTo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	logger := slog.New(handler)

	source := EventSource{
		Type:  SourceTypeNetwork,
		Value: "192.168.1.100",
		Extra: map[string]any{subjKeyUserAgent: "test-agent"},
	}
	subjects := map[string]string{
		subjKeyUser:   "testuser",
		subjKeyUserID: "user123",
	}
	target := map[string]string{
		targetKeyType:  targetTypeTool,
		targetKeyName:  "calculator",
		targetKeyEndpt: "/api/tools/calculator",
	}

	event := NewAuditEvent("mcp_tool_call", source, OutcomeSuccess, subjects, "test-component")
	event.WithTarget(target)
	event.Metadata.Extra = map[string]any{
		"duration_ms": 150,
		"transport":   "sse",
	}

	customLevel := slog.Level(2)
	event.LogTo(context.Background(), logger, customLevel)

	logOutput := buf.String()
	require.NotEmpty(t, logOutput)

	var logEntry map[string]any
	err := json.Unmarshal([]byte(logOutput), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "audit_event", logEntry["msg"])
	assert.Equal(t, event.Metadata.AuditID, logEntry["audit_id"])
	assert.Equal(t, "mcp_tool_call", logEntry["type"])
	assert.Equal(t, OutcomeSuccess, logEntry["outcome"])
	assert.Equal(t, "test-component", logEntry["component"])

	sourceData, ok := logEntry["source"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, SourceTypeNetwork, sourceData["type"])
	assert.Equal(t, "192.168.1.100", sourceData["value"])

	subjectsData, ok := logEntry["subjects"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "testuser", subjectsData[subjKeyUser])
	assert.Equal(t, "user123", subjectsData[subjKeyUserID])

	targetData, ok := logEntry["target"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, targetTypeTool, targetData[targetKeyType])
	assert.Equal(t, "calculator", targetData[targetKeyName])
	assert.Equal(t, "/api/tools/calculator", targetData[targetKeyEndpt])
}

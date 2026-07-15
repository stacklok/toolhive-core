// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"slices"
	"strings"
)

// bannedServiceSegment is the unqualified service segment banned by RFC §3.2
// (D3): "gateway" is a role shared by both the LLM Gateway and vMCP, so it
// cannot be a namespace segment on its own. A qualified segment such as
// "ai_gateway" is unaffected.
const bannedServiceSegment = "gateway"

// minNameSegments is the minimum number of dotted segments required for a
// well-formed stacklok.<service>.<subsystem>.<name> metric name.
const minNameSegments = 4

// namePrefix is the required first segment of a Stacklok-authored metric
// name (RFC §3.2 D1: stacklok.<service>.<subsystem>.<name>).
const namePrefix = "stacklok"

// ValidateName is a build-time lint, not a runtime check. It rejects a
// dotted OTel metric name that does not match the
// stacklok.<service>.<subsystem>.<name> shape (RFC §3.2 D1), that uses
// "gateway" as its service segment, and rejects an empty or malformed name.
func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("metric name must not be empty")
	}

	segments := strings.Split(name, ".")
	if len(segments) < minNameSegments {
		return fmt.Errorf("metric name %q must have at least %d dotted segments "+
			"(stacklok.<service>.<subsystem>.<name>), got %d", name, minNameSegments, len(segments))
	}

	if slices.Contains(segments, "") {
		return fmt.Errorf("metric name %q must not have an empty dotted segment", name)
	}

	if segments[0] != namePrefix {
		return fmt.Errorf("metric name %q must start with %q "+
			"(stacklok.<service>.<subsystem>.<name>)", name, namePrefix)
	}

	service := segments[1]
	if service == bannedServiceSegment {
		return fmt.Errorf("metric name %q uses banned service segment %q; "+
			"namespace by product name instead (e.g. ai_gateway, vmcp)", name, bannedServiceSegment)
	}

	return nil
}

// replacedLabelKeys maps a banned re-spelling of a canonical label key (RFC
// §3.3 "Replaces" column) to the canonical key it must be spelled as. This
// keeps the join-key contract intact even for emitters (e.g. the LLM
// Gateway) that mirror these constants locally instead of importing them.
var replacedLabelKeys = map[string]string{
	"server":                LabelMCPServer,
	"target.workload_name":  LabelMCPServer,
	"target.workload_id":    LabelMCPServer,
	"status":                LabelOutcome,
	"success":               LabelOutcome,
	"failure":               LabelOutcome,
	"mcp.method.name":       LabelMCPMethod,
	"tool":                  LabelToolName,
	"workflow.name":         LabelCompositeTool,
	"target.transport_type": LabelTransport,
}

// ValidateLabelKind is a build-time lint, not a runtime check. It rejects a
// boolean-typed label value (RFC §3.3 forbids boolean labels because they
// duplicate the outcome/error_type dimensions), and rejects a label key that
// re-spells a canonical concept under a banned alias instead of its
// canonical key (RFC §3.3 "Replaces" column).
func ValidateLabelKind(key string, value any) error {
	if canonical, banned := replacedLabelKeys[key]; banned {
		return fmt.Errorf("label %q is a banned re-spelling of canonical key %q", key, canonical)
	}

	switch value.(type) {
	case bool, *bool:
		return fmt.Errorf("label %q must not be boolean-typed", key)
	default:
		return nil
	}
}

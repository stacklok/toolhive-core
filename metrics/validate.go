// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"fmt"
	"strings"
)

// bannedServiceSegment is the unqualified service segment banned by RFC §3.2
// (D3): "gateway" is a role shared by both the LLM Gateway and vMCP, so it
// cannot be a namespace segment on its own. A qualified segment such as
// "llm_gateway" is unaffected.
const bannedServiceSegment = "gateway"

// minNameSegments is the minimum number of dotted segments required for a
// well-formed stacklok.<service>.<subsystem>.<name> metric name.
const minNameSegments = 4

// ValidateName is a build-time lint, not a runtime check. It rejects a
// dotted OTel metric name (stacklok.<service>.<subsystem>.<name>) that uses
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

	service := segments[1]
	if service == bannedServiceSegment {
		return fmt.Errorf("metric name %q uses banned service segment %q; "+
			"namespace by product name instead (e.g. llm_gateway, vmcp)", name, bannedServiceSegment)
	}

	return nil
}

// ValidateLabelKind is a build-time lint, not a runtime check. It rejects a
// boolean-typed label value; RFC §3.3 forbids boolean labels because they
// duplicate the outcome/error_type dimensions.
func ValidateLabelKind(key string, value any) error {
	switch value.(type) {
	case bool, *bool:
		return fmt.Errorf("label %q must not be boolean-typed", key)
	default:
		return nil
	}
}

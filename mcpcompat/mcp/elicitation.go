// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import "fmt"

// ElicitationRequest is a request from the server to the client to request additional
// information from the user during an interaction.
type ElicitationRequest struct {
	Request
	Params ElicitationParams `json:"params"`
}

// ElicitationParams contains the parameters for an elicitation request.
type ElicitationParams struct {
	Meta *Meta `json:"_meta,omitempty"`
	// Mode specifies the type of elicitation: "form" or "url". Defaults to "form".
	Mode string `json:"mode,omitempty"`
	// A human-readable message explaining what information is being requested and why.
	Message string `json:"message"`

	// Form mode fields

	// A JSON Schema defining the expected structure of the user's response.
	RequestedSchema any `json:"requestedSchema,omitempty"`

	// URL mode fields

	// ElicitationID is a unique identifier for the elicitation request.
	ElicitationID string `json:"elicitationId,omitempty"`
	// URL is the URL to be opened by the user.
	URL string `json:"url,omitempty"`
}

// ElicitationResult represents the result of an elicitation request.
type ElicitationResult struct {
	Result
	ElicitationResponse
}

// ElicitationResponse represents the user's response to an elicitation request.
type ElicitationResponse struct {
	// Action indicates whether the user accepted, declined, or cancelled.
	Action ElicitationResponseAction `json:"action"`
	// Content contains the user's response data if they accepted.
	// Should conform to the requestedSchema from the ElicitationRequest.
	Content any `json:"content,omitempty"`
}

// ElicitationResponseAction indicates how the user responded to an elicitation request.
type ElicitationResponseAction string

// Validate checks if the elicitation parameters are valid.
func (p ElicitationParams) Validate() error {
	mode := p.Mode
	if mode == "" {
		mode = ElicitationModeForm
	}

	switch mode {
	case ElicitationModeForm:
		if p.RequestedSchema == nil {
			return fmt.Errorf("requestedSchema is required for form elicitation")
		}
	case ElicitationModeURL:
		if p.ElicitationID == "" {
			return fmt.Errorf("elicitationId is required for url elicitation")
		}
		if p.URL == "" {
			return fmt.Errorf("url is required for url elicitation")
		}
	default:
		return fmt.Errorf("invalid elicitation mode: %s", mode)
	}

	return nil
}

// Elicitation response actions.
const (
	// ElicitationResponseActionAccept indicates the user provided the requested information.
	ElicitationResponseActionAccept ElicitationResponseAction = "accept"
	// ElicitationResponseActionDecline indicates the user explicitly declined to provide information.
	ElicitationResponseActionDecline ElicitationResponseAction = "decline"
	// ElicitationResponseActionCancel indicates the user cancelled without making a choice.
	ElicitationResponseActionCancel ElicitationResponseAction = "cancel"
)

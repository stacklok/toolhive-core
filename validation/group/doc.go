// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package group provides validation functions for group names.

Group names are used to organize and categorize resources. This package ensures
group names follow consistent naming conventions for compatibility across systems.

# Name Validation

Validate group names against naming rules:

	if err := group.ValidateName("my-team"); err != nil {
		// Handle invalid group name
	}

Valid group names must:
  - Be non-empty (not just whitespace)
  - Contain only lowercase alphanumeric characters, underscores, dashes, and spaces
  - Not contain null bytes
  - Not have leading or trailing whitespace
  - Not contain consecutive spaces

# Examples

Valid names:

	"teamalpha"
	"team-alpha"
	"team_alpha_123"
	"team alpha"

Invalid names:

	""                  // empty
	"TeamAlpha"         // uppercase
	"team@alpha"        // special characters
	" teamalpha"        // leading space
	"team  alpha"       // consecutive spaces
*/
package group

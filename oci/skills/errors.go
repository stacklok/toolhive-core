// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package skills

import "errors"

// Sentinel errors returned (wrapped) by the packager so callers can classify
// failures with errors.Is instead of matching error message strings. The
// underlying error message is preserved at each call site via fmt.Errorf
// with %w; only the classification is added.
var (
	// ErrInvalidSkillDir indicates the skill directory is missing, not a
	// directory, or otherwise unsafe to read (e.g. contains path traversal).
	ErrInvalidSkillDir = errors.New("invalid skill directory")

	// ErrSkillMDMissing indicates SKILL.md is not present in the skill
	// directory.
	ErrSkillMDMissing = errors.New("SKILL.md missing")

	// ErrInvalidFrontmatter indicates the SKILL.md YAML frontmatter is
	// missing, malformed, oversized, or missing required fields such as
	// the skill name.
	ErrInvalidFrontmatter = errors.New("invalid SKILL.md frontmatter")

	// ErrTooManyFiles indicates the skill directory exceeds the maximum
	// allowed number of files.
	ErrTooManyFiles = errors.New("too many files in skill directory")

	// ErrSkillTooLarge indicates the skill directory exceeds the maximum
	// allowed total size.
	ErrSkillTooLarge = errors.New("skill directory too large")

	// ErrInvalidSkillFile indicates a per-file issue inside the skill
	// directory: a symlink, a non-regular file, or an unreadable entry.
	ErrInvalidSkillFile = errors.New("invalid skill file")
)

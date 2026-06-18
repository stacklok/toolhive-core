// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package plugins

const (
	testFileA             = "a.txt"
	testFileB             = "b.txt"
	testPluginMyPlugin    = "my-plugin"
	testNotJSON           = "not-json"
	testNameInvalidJSON   = "invalid JSON"
	testComponentCommands = "commands"
	testPluginComponents  = `{"commands":1,"agents":1,"skills":1,"hooks":1,"mcpServers":1}`
	testPlatformAMD64     = "linux/amd64"
	testPlatformARMv7     = "linux/arm/v7"
	testArchARM           = "arm"
	testComponentSkills   = "skills"
	testPluginMinimal     = "minimal-plugin"
	testRequireServerV1   = "ghcr.io/org/server:v1"
	testRequireSkillV1    = "ghcr.io/org/skill:v1"
)

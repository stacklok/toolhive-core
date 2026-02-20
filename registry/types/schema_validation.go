// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed data/toolhive-legacy-registry.schema.json data/upstream-registry.schema.json data/publisher-provided.schema.json data/skill.schema.json
var embeddedSchemaFS embed.FS

// Validate validates the Registry against the legacy ToolHive registry schema.
func (r *Registry) Validate() error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to serialize registry: %w", err)
	}
	return validateAgainstSchema(data, "data/toolhive-legacy-registry.schema.json", "registry schema validation failed")
}

// Validate validates the UpstreamRegistry against the upstream registry schema.
// It also validates any publisher-provided extensions found in server definitions.
func (r *UpstreamRegistry) Validate() error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("failed to serialize upstream registry: %w", err)
	}
	if err := validateAgainstSchema(data, "data/upstream-registry.schema.json", "registry schema validation failed"); err != nil {
		return err
	}
	return validateRegistryExtensions(data)
}

// Validate validates the ServerExtensions against the publisher-provided schema.
func (e *ServerExtensions) Validate() error {
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("failed to serialize server extensions: %w", err)
	}
	const schemaFile = "data/publisher-provided.schema.json"
	return validateAgainstSchema(data, schemaFile, "publisher-provided extensions schema validation failed")
}

// Validate validates the Skill against the skill schema.
func (s *Skill) Validate() error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("failed to serialize skill: %w", err)
	}
	return validateAgainstSchema(data, "data/skill.schema.json", "skill schema validation failed")
}

// ValidateRegistrySchema validates raw registry JSON bytes against the legacy ToolHive registry schema.
func ValidateRegistrySchema(registryData []byte) error {
	return validateAgainstSchema(registryData, "data/toolhive-legacy-registry.schema.json", "registry schema validation failed")
}

// ValidateUpstreamRegistryBytes validates raw upstream registry JSON bytes against the upstream registry schema.
// It also validates any publisher-provided extensions found in server definitions.
func ValidateUpstreamRegistryBytes(registryData []byte) error {
	const schemaFile = "data/upstream-registry.schema.json"
	if err := validateAgainstSchema(registryData, schemaFile, "registry schema validation failed"); err != nil {
		return err
	}
	return validateRegistryExtensions(registryData)
}

// ValidatePublisherProvidedExtensionsBytes validates raw publisher-provided extensions JSON bytes.
func ValidatePublisherProvidedExtensionsBytes(extensionsData []byte) error {
	const schemaFile = "data/publisher-provided.schema.json"
	return validateAgainstSchema(extensionsData, schemaFile, "publisher-provided extensions schema validation failed")
}

// ValidateSkillBytes validates raw skill JSON bytes against the skill schema.
func ValidateSkillBytes(skillData []byte) error {
	return validateAgainstSchema(skillData, "data/skill.schema.json", "skill schema validation failed")
}

// ValidateServerJSON validates a single MCP server JSON object and optionally validates
// any publisher-provided extensions found in its _meta field.
func ValidateServerJSON(serverData []byte, validateExtensions bool) error {
	var server map[string]any
	if err := json.Unmarshal(serverData, &server); err != nil {
		return fmt.Errorf("invalid server JSON: %w", err)
	}
	if !validateExtensions {
		return nil
	}
	serverName := getServerName(server, 0)
	return validateServerExtensions(server, serverName)
}

// validateAgainstSchema validates data against a named embedded schema file.
func validateAgainstSchema(data []byte, schemaFile, errPrefix string) error {
	schemaData, err := embeddedSchemaFS.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to read embedded schema %s: %w", schemaFile, err)
	}

	result, err := gojsonschema.Validate(
		gojsonschema.NewBytesLoader(schemaData),
		gojsonschema.NewBytesLoader(data),
	)
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	if result.Valid() {
		return nil
	}

	msgs := make([]string, 0, len(result.Errors()))
	for _, desc := range result.Errors() {
		msgs = append(msgs, desc.String())
	}
	return formatNumberedErrors(errPrefix, msgs)
}

// formatNumberedErrors formats a list of messages as a single error with a numbered list.
func formatNumberedErrors(prefix string, msgs []string) error {
	if len(msgs) == 0 {
		return nil
	}
	if len(msgs) == 1 {
		return fmt.Errorf("%s: %s", prefix, msgs[0])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s with %d errors:\n", prefix, len(msgs))
	for i, msg := range msgs {
		fmt.Fprintf(&b, "  %d. %s\n", i+1, msg)
	}
	return errors.New(strings.TrimSuffix(b.String(), "\n"))
}

// validateRegistryExtensions parses the registry and validates publisher-provided extensions in all servers.
func validateRegistryExtensions(registryData []byte) error {
	var registryMap map[string]any
	if err := json.Unmarshal(registryData, &registryMap); err != nil {
		return fmt.Errorf("failed to parse registry JSON: %w", err)
	}

	data, ok := registryMap["data"].(map[string]any)
	if !ok {
		return nil
	}

	var errs []string
	if servers, ok := data["servers"].([]any); ok {
		errs = append(errs, validateServerList(servers, "")...)
	}
	if groups, ok := data["groups"].([]any); ok {
		errs = append(errs, validateGroupServers(groups)...)
	}

	return formatExtensionErrors(errs)
}

func validateGroupServers(groups []any) []string {
	var errs []string
	for _, group := range groups {
		groupMap, ok := group.(map[string]any)
		if !ok {
			continue
		}
		groupName, _ := groupMap["name"].(string)
		if groupServers, ok := groupMap["servers"].([]any); ok {
			errs = append(errs, validateServerList(groupServers, groupName)...)
		}
	}
	return errs
}

func validateServerList(servers []any, groupName string) []string {
	var errs []string
	for i, server := range servers {
		serverMap, ok := server.(map[string]any)
		if !ok {
			continue
		}
		serverName := getServerName(serverMap, i)
		if groupName != "" {
			serverName = fmt.Sprintf("group[%s].%s", groupName, serverName)
		}
		if err := validateServerExtensions(serverMap, serverName); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func formatExtensionErrors(errs []string) error {
	return formatNumberedErrors("publisher-provided extensions validation failed", errs)
}

func validateServerExtensions(server map[string]any, serverName string) error {
	meta, ok := server["_meta"].(map[string]any)
	if !ok {
		return nil
	}
	publisherProvided, ok := meta[PublisherProvidedKey].(map[string]any)
	if !ok {
		return nil
	}
	extensionsData, err := json.Marshal(publisherProvided)
	if err != nil {
		return fmt.Errorf("server %s: failed to serialize extensions: %w", serverName, err)
	}
	if err := ValidatePublisherProvidedExtensionsBytes(extensionsData); err != nil {
		return fmt.Errorf("server %s: %w", serverName, err)
	}
	return nil
}

func getServerName(server map[string]any, index int) string {
	if name, ok := server["name"].(string); ok && name != "" {
		return name
	}
	return fmt.Sprintf("servers[%d]", index)
}

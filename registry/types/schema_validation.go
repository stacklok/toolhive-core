// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/xeipuuv/gojsonschema"
)

//go:embed data/upstream-registry.schema.json data/publisher-provided.schema.json data/skill.schema.json data/server.schema.json data/plugin.schema.json
var embeddedSchemaFS embed.FS

// referencedSchemas lists embedded schema files that declare an $id matching
// a $ref in other schemas. They are preloaded into every SchemaLoader so the
// validator never needs to fetch them over the network.
var referencedSchemas = []string{
	"data/server.schema.json",
	"data/skill.schema.json",
	"data/plugin.schema.json",
}

// preloadedSchemaLoaders caches the raw bytes of each referenced schema,
// keyed by its embedded file path. Built once via preloadOnce.
var (
	preloadOnce          sync.Once
	preloadedSchemaBytes [][]byte
	preloadErr           error
)

// ensurePreloaded reads the referenced schema files once and caches their
// bytes for reuse across every call to validateAgainstSchema.
func ensurePreloaded() error {
	preloadOnce.Do(func() {
		preloadedSchemaBytes = make([][]byte, 0, len(referencedSchemas))
		for _, path := range referencedSchemas {
			data, err := embeddedSchemaFS.ReadFile(path)
			if err != nil {
				preloadErr = fmt.Errorf("failed to read embedded referenced schema %s: %w", path, err)
				return
			}
			preloadedSchemaBytes = append(preloadedSchemaBytes, data)
		}
	})
	return preloadErr
}

// Validate validates the UpstreamRegistry against the upstream registry schema.
// It also validates any publisher-provided extensions found in server definitions.
func (r *UpstreamRegistry) Validate() error {
	data, err := json.Marshal(r)
	if err != nil {
		return errors.New("failed to serialize upstream registry")
	}
	return ValidateUpstreamRegistryBytes(data)
}

// Validate validates the ServerExtensions against the publisher-provided schema.
func (e *ServerExtensions) Validate() error {
	data, err := json.Marshal(e)
	if err != nil {
		return errors.New("failed to serialize server extensions")
	}
	const schemaFile = "data/publisher-provided.schema.json"
	return validateAgainstSchema(data, schemaFile, "publisher-provided extensions schema validation failed")
}

// Validate validates the Skill against the skill schema.
func (s *Skill) Validate() error {
	data, err := json.Marshal(s)
	if err != nil {
		return errors.New("failed to serialize skill")
	}
	return validateAgainstSchema(data, "data/skill.schema.json", "skill schema validation failed")
}

// Validate validates the Plugin against the plugin schema.
func (p *Plugin) Validate() error {
	data, err := json.Marshal(p)
	if err != nil {
		return errors.New("failed to serialize plugin")
	}
	return validateAgainstSchema(data, "data/plugin.schema.json", "plugin schema validation failed")
}

// ValidateUpstreamRegistryBytes validates strict original registry JSON against
// the embedded schemas, including MCP 2025-12-11 servers. ToolHive publisher
// extension policy is always enabled for whole registries.
func ValidateUpstreamRegistryBytes(registryData []byte) error {
	value, err := validateJSONAgainstSchema(registryData, "data/upstream-registry.schema.json", "registry schema validation failed")
	if err != nil {
		return err
	}
	return validateRegistryExtensions(value.(map[string]any))
}

// ValidatePublisherProvidedExtensionsBytes validates strict original publisher
// metadata JSON, requiring object-valued namespaces and ToolHive schema compliance.
func ValidatePublisherProvidedExtensionsBytes(extensionsData []byte) error {
	const schemaFile = "data/publisher-provided.schema.json"
	return validateAgainstSchema(extensionsData, schemaFile, "publisher-provided extensions schema validation failed")
}

// ValidateSkillBytes validates strict original skill JSON against the embedded skill schema.
func ValidateSkillBytes(skillData []byte) error {
	return validateAgainstSchema(skillData, "data/skill.schema.json", "skill schema validation failed")
}

// ValidatePluginBytes validates strict original plugin JSON against the embedded plugin schema.
func ValidatePluginBytes(pluginData []byte) error {
	return validateAgainstSchema(pluginData, "data/plugin.schema.json", "plugin schema validation failed")
}

// ValidateServerJSON validates the original JSON against the embedded MCP 2025-12-11
// server schema, without fetching the submitted $schema URL. validateExtensions
// only enables additional ToolHive publisher namespace policy; it never disables
// MCP validation. All raw validators reject duplicate decoded object names,
// invalid UTF-8 or Unicode escapes, and anything other than one complete JSON value.
func ValidateServerJSON(serverData []byte, validateExtensions bool) error {
	value, err := validateJSONAgainstSchema(serverData, "data/server.schema.json", "server schema validation failed")
	if err != nil {
		return err
	}
	if !validateExtensions {
		return nil
	}
	return validateServerExtensions(value.(map[string]any), "server")
}

// decodeJSON preserves unconstrained JSON numbers, including values outside the
// float64 range. Callers must validate original bytes before normalizing them.
func decodeJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errors.New("invalid JSON")
	}
	return nil
}

func validateJSONAgainstSchema(data []byte, schemaFile, errPrefix string) (any, error) {
	if !jsontext.Value(data).IsValid() {
		return nil, fmt.Errorf("%s: invalid JSON", errPrefix)
	}
	var value any
	if err := decodeJSON(data, &value); err != nil {
		return nil, err
	}
	return value, validateValueAgainstSchema(value, schemaFile, errPrefix)
}

// validateAgainstSchema checks strict original JSON before schema validation.
func validateAgainstSchema(data []byte, schemaFile, errPrefix string) error {
	_, err := validateJSONAgainstSchema(data, schemaFile, errPrefix)
	return err
}

// validateValueAgainstSchema only accepts values decoded from already checked
// JSON. Referenced schemas are embedded; instance $schema URLs are never loaded.
func validateValueAgainstSchema(value any, schemaFile, errPrefix string) error {
	if err := ensurePreloaded(); err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	schemaData, err := embeddedSchemaFS.ReadFile(schemaFile)
	if err != nil {
		return fmt.Errorf("failed to read embedded schema %s: %w", schemaFile, err)
	}

	sl := gojsonschema.NewSchemaLoader()
	for i, refPath := range referencedSchemas {
		// Skip preloading a schema that is the same file being compiled;
		// Compile will register it via its $id and a duplicate would
		// cause a "Reference already exists" error.
		if refPath == schemaFile {
			continue
		}
		if err := sl.AddSchemas(gojsonschema.NewBytesLoader(preloadedSchemaBytes[i])); err != nil {
			return fmt.Errorf("%s: failed to preload referenced schema: %w", errPrefix, err)
		}
	}

	compiled, err := sl.Compile(gojsonschema.NewBytesLoader(schemaData))
	if err != nil {
		return fmt.Errorf("%s: %w", errPrefix, err)
	}

	result, err := compiled.Validate(gojsonschema.NewRawLoader(value))
	if err != nil {
		return fmt.Errorf("%s: unable to validate JSON", errPrefix)
	}

	if result.Valid() {
		return nil
	}

	// Only schema-defined names and error kinds are safe to report. Library
	// descriptions and instance paths can contain submitted secrets or keys.
	properties := make(map[string]bool)
	collectSchemaProperties(schemaData, properties)
	for _, data := range preloadedSchemaBytes {
		collectSchemaProperties(data, properties)
	}
	msgs := make([]string, 0, len(result.Errors()))
	for _, desc := range result.Errors() {
		field := "(root)"
		for _, part := range strings.Split(desc.Field(), ".") {
			if properties[part] {
				field = part
			}
		}
		if desc.Type() == "required" {
			// Required property names come from the embedded schema, not the instance.
			field, _ = desc.Details()["property"].(string)
		}
		msg := field + ": " + desc.Type()
		if desc.Type() == "format" {
			msg += fmt.Sprintf(" (%s)", desc.Details()["format"])
		}
		msgs = append(msgs, msg)
	}
	return formatNumberedErrors(errPrefix, msgs)
}

func collectSchemaProperties(data []byte, properties map[string]bool) {
	var schema any
	if json.Unmarshal(data, &schema) != nil {
		return
	}
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if names, ok := value["properties"].(map[string]any); ok {
				for name := range names {
					properties[name] = true
				}
			}
			for _, child := range value {
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(schema)
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

// validateRegistryExtensions applies policy to the already validated original value.
func validateRegistryExtensions(registryMap map[string]any) error {
	data, ok := registryMap["data"].(map[string]any)
	if !ok {
		return nil
	}

	var errs []string
	if servers, ok := data["servers"].([]any); ok {
		errs = append(errs, validateServerList(servers)...)
	}

	return formatExtensionErrors(errs)
}

func validateServerList(servers []any) []string {
	var errs []string
	for i, server := range servers {
		serverMap, ok := server.(map[string]any)
		if !ok {
			continue
		}
		if err := validateServerExtensions(serverMap, fmt.Sprintf("servers[%d]", i)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	return errs
}

func formatExtensionErrors(errs []string) error {
	return formatNumberedErrors("publisher-provided extensions validation failed", errs)
}

func validateServerExtensions(server map[string]any, location string) error {
	meta, ok := server["_meta"].(map[string]any)
	if !ok {
		return nil
	}
	publisherProvided, ok := meta[PublisherProvidedKey].(map[string]any)
	if !ok {
		return nil
	}
	if err := validateValueAgainstSchema(publisherProvided, "data/publisher-provided.schema.json",
		"publisher-provided extensions schema validation failed"); err != nil {
		return fmt.Errorf("%s: %w", location, err)
	}
	return nil
}

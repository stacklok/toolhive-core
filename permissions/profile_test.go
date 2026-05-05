// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package permissions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testProfileName         = "test"
	testNameSinglePath      = "Single path"
	testNameHostToContainer = "Host path to container path"
	testNameResourceURI     = "Resource URI"
	pathDir                 = "/path/to/dir"
	pathContainer           = "/container/path"
	pathWindowsFooBar       = `C:\foo\bar`
	mountHostToContainer    = "/host/path:/container/path"
	mountVolume             = "volume://myvolume:/container/path"
	mountSecret             = "secret://mysecret:/container/path"
	mountInjection          = "/path/with/$(rm -rf *):/container/path"
	mountTraversal          = "/path/with/../../../etc/passwd:/container/path"
	mountVolumeRmrf         = "volume://$(rm -rf *):/container/path"
)

func TestMountDeclaration_Parse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		declaration    MountDeclaration
		expectedSource string
		expectedTarget string
		expectError    bool
	}{
		{
			name:           testNameSinglePath,
			declaration:    pathDir,
			expectedSource: pathDir,
			expectedTarget: pathDir,
			expectError:    false,
		},
		{
			// In Docker, a single Windows path gets mapped to a subdirectory
			// of root with the name of the Windows path.
			// e.g. C:\foo -> /C:\\foo
			// While this behaviour is unusual, it's valid, and we should support it.
			name:           "Single path (Windows)",
			declaration:    pathWindowsFooBar,
			expectedSource: pathWindowsFooBar,
			expectedTarget: pathWindowsFooBar,
			expectError:    false,
		},
		{
			name:           testNameHostToContainer,
			declaration:    mountHostToContainer,
			expectedSource: "/host/path",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           testNameResourceURI,
			declaration:    mountVolume,
			expectedSource: "volume://myvolume",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Resource URI (Windows)",
			declaration:    "volume://C:\\Foo\\Bar:/container/path",
			expectedSource: "volume://C:\\Foo\\Bar",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Resource URI (Windows forward slashes)",
			declaration:    "volume://C:/Foo/Bar:/container/path",
			expectedSource: "volume://C:/Foo/Bar",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Resource URI (Windows mixed slashes)",
			declaration:    "volume://C:\\Foo/Bar:/container/path",
			expectedSource: "volume://C:\\Foo/Bar",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Different resource URI",
			declaration:    mountSecret,
			expectedSource: "secret://mysecret",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Reject Resource URI with Windows target",
			declaration:    "volume://C:\\Foo\\Bar:C:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		{
			name:           "Reject Resource URI with Windows source and target",
			declaration:    "volume://foo/bar:C:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		{
			name:           "Reject Resource URI with backslashes in target",
			declaration:    "volume://C:\\Foo\\Bar:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		// Security-focused tests
		{
			name:           "Path with spaces",
			declaration:    "/path with spaces:/container/path",
			expectedSource: "/path with spaces",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Path with special characters",
			declaration:    "/path/with/special/chars!@#:/container/path",
			expectedSource: "/path/with/special/chars!@#",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Path with Unicode characters",
			declaration:    "/path/with/unicode/😀:/container/path",
			expectedSource: "/path/with/unicode/😀",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Windows style path",
			declaration:    "C:\\path\\to\\dir:/container/path",
			expectedSource: "C:\\path\\to\\dir",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Windows style path (forward slashes)",
			declaration:    "C:/path/to/dir:/container/path",
			expectedSource: "C:/path/to/dir",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Windows style path (mixed slashes)",
			declaration:    "C:\\path/to\\dir:/container/path", // Yes, this is allowed on Windows...
			expectedSource: "C:\\path/to\\dir",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Reject Windows style path for target",
			declaration:    "/foo/bar:C:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		{
			name:           "Reject backslashes in target",
			declaration:    "/foo/bar:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		{
			name:           "Reject Windows style path for source and target",
			declaration:    "C:\\path/to\\dir:C:\\container\\path",
			expectedSource: "",
			expectedTarget: "",
			expectError:    true,
		},
		{
			name:           "Path with trailing slash",
			declaration:    "/path/to/dir/:/container/path/",
			expectedSource: pathDir,
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Path with multiple slashes",
			declaration:    "/path//to///dir:/container//path",
			expectedSource: pathDir,
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Path with Unicode characters",
			declaration:    "/path/with/unicode/😀:/container/path",
			expectedSource: "/path/with/unicode/😀",
			expectedTarget: pathContainer,
			expectError:    false,
		},
		{
			name:           "Path with potential command injection",
			declaration:    mountInjection,
			expectedSource: "",
			expectedTarget: "",
			expectError:    true, // Now expecting an error due to validation
		},
		{
			name:           "Path with potential path traversal",
			declaration:    mountTraversal,
			expectedSource: "/etc/passwd", // filepath.Clean resolves the path
			expectedTarget: pathContainer,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			source, target, err := tt.declaration.Parse()

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedSource, source)
			assert.Equal(t, tt.expectedTarget, target)
		})
	}
}

func TestMountDeclaration_IsValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		declaration MountDeclaration
		expected    bool
	}{
		{
			name:        testNameSinglePath,
			declaration: pathDir,
			expected:    true,
		},
		{
			name:        testNameHostToContainer,
			declaration: mountHostToContainer,
			expected:    true,
		},
		{
			name:        testNameResourceURI,
			declaration: mountVolume,
			expected:    true,
		},
		{
			name:        "Empty string",
			declaration: "",
			expected:    true, // Empty string is treated as a single path
		},
		// Security-focused tests
		{
			name:        "Path with potential command injection",
			declaration: mountInjection,
			expected:    false, // Now invalid due to validation
		},
		{
			name:        "Path with potential path traversal",
			declaration: mountTraversal,
			expected:    true, // Valid format, but potentially dangerous
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.declaration.IsValid())
		})
	}
}

func TestMountDeclaration_IsResourceURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		declaration MountDeclaration
		expected    bool
	}{
		{
			name:        testNameSinglePath,
			declaration: pathDir,
			expected:    false,
		},
		{
			name:        testNameHostToContainer,
			declaration: mountHostToContainer,
			expected:    false,
		},
		{
			name:        testNameResourceURI,
			declaration: mountVolume,
			expected:    true,
		},
		{
			name:        "Different resource URI",
			declaration: mountSecret,
			expected:    true,
		},
		// Security-focused tests
		{
			name:        "Malformed resource URI",
			declaration: "volume:/myvolume:/container/path", // Missing a slash
			expected:    false,
		},
		{
			name:        "Resource URI with potential command injection",
			declaration: mountVolumeRmrf,
			expected:    true, // Valid format, but potentially dangerous
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.declaration.IsResourceURI())
		})
	}
}

func TestMountDeclaration_GetResourceType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		declaration  MountDeclaration
		expectedType string
		expectError  bool
	}{
		{
			name:         testNameSinglePath,
			declaration:  pathDir,
			expectedType: "",
			expectError:  true,
		},
		{
			name:         testNameHostToContainer,
			declaration:  mountHostToContainer,
			expectedType: "",
			expectError:  true,
		},
		{
			name:         "Volume resource URI",
			declaration:  mountVolume,
			expectedType: "volume",
			expectError:  false,
		},
		{
			name:         "Secret resource URI",
			declaration:  mountSecret,
			expectedType: "secret",
			expectError:  false,
		},
		// Security-focused tests
		{
			name:         "Resource URI with potential command injection",
			declaration:  mountVolumeRmrf,
			expectedType: "volume",
			expectError:  false, // Valid format, but potentially dangerous
		},
		{
			name:         "Resource URI with unusual scheme",
			declaration:  "file://etc/passwd:/container/path",
			expectedType: "file",
			expectError:  false, // Valid format, but potentially dangerous
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resourceType, err := tt.declaration.GetResourceType()

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, resourceType)
		})
	}
}

func TestParseMountDeclarations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		declarations []string
		expectError  bool
	}{
		{
			name: "Valid declarations",
			declarations: []string{
				pathDir,
				mountHostToContainer,
				mountVolume,
			},
			expectError: false,
		},
		{
			name:         "Empty list",
			declarations: []string{},
			expectError:  false,
		},
		// Security-focused tests
		{
			name: "Declarations with potential security issues",
			declarations: []string{
				mountInjection,
				mountVolumeRmrf,
				mountTraversal,
			},
			expectError: true, // Now expecting an error due to validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mounts, err := ParseMountDeclarations(tt.declarations)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, len(tt.declarations), len(mounts))
		})
	}
}

// Additional security-focused tests

func TestMountDeclaration_SecurityValidation(t *testing.T) {
	t.Parallel()
	// These tests check that our parsing is robust against various security issues

	// Test for path traversal - this should be cleaned but allowed
	traversalMount := MountDeclaration("/etc/passwd:" + pathContainer)
	source, target, err := traversalMount.Parse()
	require.NoError(t, err)
	assert.Equal(t, "/etc/passwd", source)
	assert.Equal(t, pathContainer, target)

	// Test for command injection - this should be rejected
	injectionMount := MountDeclaration("$(rm -rf *):/container/path")
	_, _, err = injectionMount.Parse()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "potential command injection")

	// Test for null byte injection - this should be rejected
	nullByteMount := MountDeclaration("/path/with/null\x00byte:/container/path")
	_, _, err = nullByteMount.Parse()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "null byte detected")
}

func TestMountDeclaration_EdgeCases(t *testing.T) {
	t.Parallel()
	// Test with multiple colons - should fail with a clear error message
	multipleColons := MountDeclaration("/path:with:multiple:colons:/container/path")
	_, _, err := multipleColons.Parse()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mount declaration format")

	// Test with very long paths
	longPath := "/very/long/path/" + strings.Repeat("a", 1000)
	longMount := MountDeclaration(longPath + ":" + pathContainer)
	source, target, err := longMount.Parse()
	require.NoError(t, err)
	assert.Equal(t, longPath, source)
	assert.Equal(t, pathContainer, target)

	// Test with path containing "://" but not at the beginning
	pathWithColon := MountDeclaration("/some/other/path/://:/tmp/foo")
	_, _, err = pathWithColon.Parse()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mount declaration format")
}

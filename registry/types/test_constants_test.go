// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package registry

const (
	testVersion          = "1.0.0"
	testServerName       = "server-a"
	testRemoteName       = "remote-a"
	testStatusActive     = "active"
	testNamespace        = "io.github.stacklok"
	testPluginName       = "pdf-processor"
	testShortDesc        = "Extract text and tables"
	testLongDesc         = "Extract text and tables from PDF files"
	testRegistryType     = "oci"
	testRegistryTypeGit  = "git"
	testPluginIdentifier = "ghcr.io/stacklok/plugins/pdf-processor:1.0.0"
	errKeyVersion        = "version"
	errKeyLastUpdated    = "last_updated"
	errKeyDescription    = "description"
	errKeyStatus         = "status"
	errKeyTier           = "tier"
	errKeyNamespace      = "namespace"
	errKeyName           = "name"
	errKeyRegistryType   = "registryType"
)

// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureADBeforeConnect_ReturnsHookWithoutContactingAzure verifies the
// constructor returns a non-nil hook with no error, deterministically and
// without any ambient Azure credentials: unlike GCP's
// google.DefaultTokenSource (see gcpiam.go's doc comment), azidentity's
// DefaultAzureCredential resolves lazily, on the first GetToken call, so
// construction alone never contacts Azure or requires credentials to be
// present. Actually invoking the returned hook would require real Azure
// credentials and is out of scope for unit tests — same posture as
// TestAwsRDSIAMBeforeConnect_ReturnsHookForStaticRegion.
func TestAzureADBeforeConnect_ReturnsHookWithoutContactingAzure(t *testing.T) {
	t.Parallel()
	fn, err := azureADBeforeConnect()
	require.NoError(t, err)
	assert.NotNil(t, fn)
}

// No equivalent GCP constructor test exists: unlike AWS and Azure,
// google.DefaultTokenSource (gcpCloudSQLIAMBeforeConnect's first call)
// resolves Application Default Credentials eagerly and returns an error
// immediately when none are found, rather than deferring resolution to the
// first token fetch. That makes even "does the constructor return a non-nil
// hook" environment-dependent — a machine with real GCP credentials
// configured would get a different, equally valid result. See gcpiam.go's
// newGCPTokenSource doc comment.

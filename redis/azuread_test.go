// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureADTokenFunc_ReturnsFuncWithoutContactingAzure verifies the
// constructor returns a non-nil TokenFunc with no error, deterministically
// and without any ambient Azure credentials: azidentity's
// DefaultAzureCredential resolves lazily, on the first GetToken call, so
// construction alone never contacts Azure or requires credentials to be
// present. Actually invoking the returned func would require real Azure
// credentials and is out of scope for unit tests.
func TestAzureADTokenFunc_ReturnsFuncWithoutContactingAzure(t *testing.T) {
	t.Parallel()
	fn, err := azureADTokenFunc()
	require.NoError(t, err)
	assert.NotNil(t, fn)
}

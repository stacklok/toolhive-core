#!/bin/sh
# SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

./scripts/validate-release.sh redisconn/v1.2.3 >/dev/null

if ./scripts/validate-release.sh v1.2.3 >/dev/null 2>&1; then
	echo "root release unexpectedly accepted development sibling versions" >&2
	exit 1
fi
if ./scripts/validate-release.sh redisconn/aws/v1.2.3 >/dev/null 2>&1; then
	echo "provider release unexpectedly accepted development core version" >&2
	exit 1
fi
if ./scripts/validate-release.sh redisconn/not-a-version >/dev/null 2>&1; then
	echo "malformed release tag unexpectedly accepted" >&2
	exit 1
fi
if ./scripts/validate-release.sh aws/v1.2.3 >/dev/null 2>&1; then
	echo "incorrect module tag prefix unexpectedly accepted" >&2
	exit 1
fi

echo "release manifest validation tests passed"

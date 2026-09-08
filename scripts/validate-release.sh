#!/bin/sh
# SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <release-tag>" >&2
	exit 2
fi

tag=$1

case "$tag" in
	redisconn/aws/v*) dir=redisconn/aws; expected=github.com/stacklok/toolhive-core/redisconn/aws ;;
	redisconn/azure/v*) dir=redisconn/azure; expected=github.com/stacklok/toolhive-core/redisconn/azure ;;
	redisconn/gcp/v*) dir=redisconn/gcp; expected=github.com/stacklok/toolhive-core/redisconn/gcp ;;
	redisconn/v*) dir=redisconn; expected=github.com/stacklok/toolhive-core/redisconn ;;
	v*) dir=.; expected=github.com/stacklok/toolhive-core ;;
	*) echo "invalid release tag prefix: $tag" >&2; exit 1 ;;
esac

version=${tag##*/}
if ! printf '%s\n' "$version" | grep -Eq '^v(0|1)\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'; then
	echo "invalid release version (module path supports v0 or v1): $tag" >&2
	exit 1
fi

manifest=$dir/go.mod
actual=$(awk '$1 == "module" { print $2; exit }' "$manifest")
if [ "$actual" != "$expected" ]; then
	echo "release tag $tag selects $expected, but $manifest declares $actual" >&2
	exit 1
fi

if grep -Eq '^[[:space:]]*github\.com/stacklok/toolhive-core/redisconn(/(aws|azure|gcp))?[[:space:]]+v0\.0\.0([[:space:]]|$)' "$manifest"; then
	echo "$manifest retains a development-only v0.0.0 Redis sibling requirement; prepare and pin released sibling versions before tagging $tag" >&2
	exit 1
fi

echo "release manifest validation passed for $tag ($manifest)"

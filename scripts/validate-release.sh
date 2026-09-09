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

requirements=$(awk '
	$1 == "require" && $2 == "(" { in_require = 1; next }
	in_require && $1 == ")" { in_require = 0; next }
	in_require && $1 ~ /^github\.com\/stacklok\/toolhive-core\/redisconn(\/(aws|azure|gcp))?$/ { print $1, $2; next }
	$1 == "require" && $2 ~ /^github\.com\/stacklok\/toolhive-core\/redisconn(\/(aws|azure|gcp))?$/ { print $2, $3 }
' "$manifest")

printf '%s\n' "$requirements" | while read -r module required_version; do
	[ -n "$module" ] || continue
	required_tag=${module#github.com/stacklok/toolhive-core/}/$required_version
	if ! git rev-parse --verify --quiet "refs/tags/$required_tag^{commit}" >/dev/null; then
		echo "$manifest requires $module $required_version, but released tag $required_tag is not available locally; fetch required previous tags before tagging $tag" >&2
		exit 1
	fi
done

echo "release manifest validation passed for $tag ($manifest)"

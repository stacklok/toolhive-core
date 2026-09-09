#!/bin/sh
# SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

core_modules=$(cd redisconn && GOWORK=off go list -m all)
printf '%s\n' "$core_modules"

for forbidden in \
	'github.com/aws/' \
	'github.com/Azure/' \
	'cloud.google.com/go/compute/metadata' \
	'google.golang.org/api' \
	'k8s.io/' \
	'github.com/stacklok/toolhive ' \
	'github.com/stacklok/dockyard' \
	'github.com/stacklok/toolhive-registry'; do
	if printf '%s\n' "$core_modules" | grep -F "$forbidden" >/dev/null; then
		echo "redisconn dependency budget violation: $forbidden" >&2
		exit 1
	fi
done

if printf '%s\n' "$core_modules" | grep -E 'github.com/stacklok/toolhive-core/redisconn/(aws|azure|gcp)' >/dev/null; then
	echo "redisconn must not depend on a provider child module" >&2
	exit 1
fi

for child in aws azure gcp; do
	child_modules=$(cd "redisconn/$child" && GOWORK=off go list -m all)
	if ! printf '%s\n' "$child_modules" | grep -E '^github.com/stacklok/toolhive-core/redisconn( |$)' >/dev/null; then
		echo "redisconn/$child does not depend on redisconn core" >&2
		exit 1
	fi
done

echo "redisconn module dependency budget passed"

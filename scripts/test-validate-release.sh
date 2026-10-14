#!/bin/sh
# SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

./scripts/validate-release.sh redisconn/v1.2.3 >/dev/null

repo_root=$(git rev-parse --show-toplevel)
validator=$repo_root/scripts/validate-release.sh
fixture=$(mktemp -d "${TMPDIR:-/tmp}/toolhive-release-fixture.XXXXXX")
cleanup() {
	case "$fixture" in
		"${TMPDIR:-/tmp}"/toolhive-release-fixture.*) rm -rf -- "$fixture" ;;
	esac
}
trap cleanup EXIT HUP INT TERM

cp scripts/testdata/release-current-core/go.mod "$fixture/go.mod"
git archive --format=tar redisconn/v0.0.2 redisconn > "$fixture/redisconn.tar"
tar -xf "$fixture/redisconn.tar" -C "$fixture"
rm "$fixture/redisconn.tar"
git -C "$fixture" init -q
git -C "$fixture" config user.email release-validation@example.com
git -C "$fixture" config user.name "Release validation test"
git -C "$fixture" add go.mod redisconn
git -C "$fixture" commit -qm "release validation fixture"
git -C "$fixture" tag --no-sign redisconn/v0.0.2

(
	cd "$fixture"
	"$validator" v1.2.3 >/dev/null
)

printf '\n// synthetic release-validation drift\n' >> "$fixture/redisconn/go.mod"
if (
	cd "$fixture"
	"$validator" v1.2.3 >/dev/null 2>&1
); then
	echo "root release unexpectedly accepted a changed synthetic redisconn child" >&2
	exit 1
fi

if (
	cd scripts/testdata/release-nonzero
	../../../scripts/validate-release.sh redisconn/aws/v1.2.3 >/dev/null 2>&1
); then
	echo "provider release unexpectedly accepted a nonexistent non-zero core version" >&2
	exit 1
fi
if (
	cd scripts/testdata/release-nonzero
	../../../scripts/validate-release.sh v1.2.3 >/dev/null 2>&1
); then
	echo "root release unexpectedly accepted nonexistent non-zero child versions" >&2
	exit 1
fi

if (
	cd scripts/testdata/release-dev-siblings
	../../../scripts/validate-release.sh v0.0.0 >/dev/null 2>&1
); then
	echo "root release unexpectedly accepted development sibling versions" >&2
	exit 1
fi
if (
	cd scripts/testdata/release-dev-siblings
	../../../scripts/validate-release.sh redisconn/aws/v0.0.0 >/dev/null 2>&1
); then
	echo "provider release unexpectedly accepted development core version" >&2
	exit 1
fi
if (
	cd scripts/testdata/release-stale-pin
	../../../scripts/validate-release.sh v1.2.3 >/dev/null 2>&1
); then
	echo "root release unexpectedly accepted a real but stale (drifted) redisconn pin" >&2
	exit 1
fi
if (
	cd scripts/testdata/release-stale-provider
	../../../scripts/validate-release.sh v1.2.3 >/dev/null 2>&1
); then
	echo "root release unexpectedly accepted a stale provider pin" >&2
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

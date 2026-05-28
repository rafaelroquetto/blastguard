#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

set -e

BLASTGUARD_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BLASTGUARDD="${BLASTGUARD_ROOT}/build/blastguardd"
BLASTGUARDCTL="${BLASTGUARD_ROOT}/build/blastguardctl"
FIXTURE="${BLASTGUARD_ROOT}/test/fixtures/evil-helper/install.sh"

if [ ! -x "$BLASTGUARDD" ] || [ ! -x "$BLASTGUARDCTL" ]; then
	echo "build blastguard first: cmake -B build && cmake --build build" >&2
	exit 1
fi

if ! command -v jq >/dev/null; then
	echo "jq is required for behavioural assertions" >&2
	exit 1
fi

echo "[run-enforce] blastguardd needs root; refreshing sudo credentials"
sudo -v

PKG_DIR="/tmp/proj/node_modules/evil-helper"
mkdir -p "$PKG_DIR"
cp "$FIXTURE" "$PKG_DIR/install.sh"
chmod +x "$PKG_DIR/install.sh"

echo "[run-enforce] starting blastguardd (enforce mode, deliberately narrow allowlist)"
sudo "$BLASTGUARDD" --mode enforce \
	--allow registry.npmjs.org \
	>/tmp/blastguardd.log 2>&1 &
DAEMON_PID=$!
sleep 0.3

cleanup() {
	"$BLASTGUARDCTL" shutdown >/dev/null 2>&1 || sudo kill "$DAEMON_PID" 2>/dev/null || true
	wait 2>/dev/null || true
}
trap cleanup EXIT

cd "$PKG_DIR"
export NPM_TOKEN=fake-npm-token-for-testing
export npm_lifecycle_event=postinstall

"$BLASTGUARDCTL" start-phase $$ install
bash install.sh
"$BLASTGUARDCTL" end-phase

REPORT_JSON="$("$BLASTGUARDCTL" report --format json)"

echo "----- report -----"
"$BLASTGUARDCTL" report --format markdown
echo "------------------"

if echo "$REPORT_JSON" | jq -e '.findings | map(select(.rule == "R2" and .blocked == true)) | length > 0' >/dev/null; then
	echo "  [PASS] C5: enforce mode produced at least one blocked R2 finding"
else
	echo "  [FAIL] C5: expected an R2 finding with blocked=true, none present"
	exit 1
fi

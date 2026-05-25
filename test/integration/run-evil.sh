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

echo "[run-evil] blastguardd needs root; refreshing sudo credentials"
sudo -v

PKG_DIR="/tmp/proj/node_modules/evil-helper"
mkdir -p "$PKG_DIR"
cp "$FIXTURE" "$PKG_DIR/install.sh"
chmod +x "$PKG_DIR/install.sh"

echo "[run-evil] starting blastguardd (audit mode)"
sudo "$BLASTGUARDD" --mode audit \
	--allow registry.npmjs.org --allow github.com --allow objects.githubusercontent.com \
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

echo "[run-evil] marking phase start"
"$BLASTGUARDCTL" start-phase $$ install

echo "[run-evil] running evil postinstall"
bash install.sh

echo "[run-evil] marking phase end"
"$BLASTGUARDCTL" end-phase

echo "[run-evil] rendering report"
"$BLASTGUARDCTL" report --format=markdown --fail-on=high
RC=$?

echo "[run-evil] exit code: $RC"
exit $RC

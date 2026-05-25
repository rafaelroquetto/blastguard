#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

set -e

ACTION_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${ACTION_DIR}/.." && pwd)"

MODE="${BLASTGUARD_MODE:-audit}"
ALLOWED_HOSTS="${BLASTGUARD_ALLOWED_HOSTS:-registry.npmjs.org,github.com,objects.githubusercontent.com}"

if [ ! -x "${ROOT}/build/blastguardd" ]; then
	(cd "${ROOT}" && cmake -B build && cmake --build build -j)
fi

ALLOW_ARGS=()
IFS=',' read -ra HOSTS <<< "${ALLOWED_HOSTS}"
for h in "${HOSTS[@]}"; do
	ALLOW_ARGS+=(-a "$h")
done

sudo "${ROOT}/build/blastguardd" --mode "${MODE}" "${ALLOW_ARGS[@]}" \
	>/tmp/blastguardd.log 2>&1 &
echo $! | sudo tee /var/run/blastguardd.pid >/dev/null
sleep 0.5

sudo cp "${ROOT}/build/blastguardctl" /usr/local/bin/blastguardctl
echo "blastguardd started in ${MODE} mode (log: /tmp/blastguardd.log)"

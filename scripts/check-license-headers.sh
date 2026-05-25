#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

set -e

missing=0

for f in "$@"; do
	if ! head -5 "$f" | grep -q 'SPDX-License-Identifier:'; then
		echo "missing license header: $f" >&2
		missing=1
	fi
done

exit $missing

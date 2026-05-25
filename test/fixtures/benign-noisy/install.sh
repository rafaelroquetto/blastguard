#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rafael Roquetto

set +e

mkdir -p /tmp/benign-install
echo "compiling..." > /tmp/benign-install/log
ls -la /tmp > /dev/null
date > /tmp/benign-install/date.txt

echo "good-helper postinstall finished"

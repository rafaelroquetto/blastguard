/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "args.h"
#include "daemon.h"

int main(int argc, char *argv[])
{
	Daemon daemon(parseArgs(argc, argv));

	if (!daemon.init())
		return 1;

	return daemon.exec();
}

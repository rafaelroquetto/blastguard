/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "args.h"

#include <array>
#include <cstdlib>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <tuple>

constexpr std::array<std::tuple<Mode, const char *>, 2> mode_table = {{
	{Mode::Audit, "audit"},
	{Mode::Enforce, "enforce"},
}};

std::string modeToString(Mode m)
{
	for (const auto &[mode, name] : mode_table)
	{
		if (mode == m)
			return name;
	}

	return {};
}

std::optional<Mode> modeFromString(std::string_view s)
{
	for (const auto &[mode, name] : mode_table)
	{
		if (s == name)
			return mode;
	}

	return std::nullopt;
}

static void usage()
{
	const char usageText[] =
		"Usage: blastguardd [options]\n"
		"  --mode <audit|enforce>     - operating mode (default: audit)\n"
		"  -a, --allow <host>         - allowlist a hostname (resolved at startup); repeatable\n"
		"  -v, --verbose              - log every event to stdout\n";

	std::println("{}", usageText);

	std::exit(EXIT_FAILURE);
}

Args parseArgs(int argc, char *argv[])
{
	Args ret;

	auto shift = [i = 0, argc, argv]() mutable -> std::string_view
	{
		if (i >= argc)
			return {};

		return argv[i++];
	};

	for (;;)
	{
		const std::string_view arg = shift();

		if (arg.empty())
			break;

		if (arg == "--mode")
		{
			const std::string_view value = shift();

			if (value.empty())
			{
				std::println(stderr, "--mode requires an argument");
				usage();
			}

			const auto m = modeFromString(value);

			if (!m)
			{
				std::println(stderr, "invalid --mode value: {}", value);
				usage();
			}

			ret.mode = *m;
		}
		else if (arg == "-a" || arg == "--allow")
		{
			const std::string_view value = shift();

			if (value.empty())
			{
				std::println(stderr, "--allow requires an argument");
				usage();
			}

			ret.allowed_hosts.emplace_back(value);
		}
		else if (arg == "-v" || arg == "--verbose")
		{
			ret.verbose = true;
		}
	}

	return ret;
}

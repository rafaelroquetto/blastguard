/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "args.h"

#include <array>
#include <charconv>
#include <cstdlib>
#include <print>
#include <string>
#include <string_view>
#include <tuple>

constexpr std::array<std::tuple<Subcommand, const char *>, 5> subcommand_table = {{
	{Subcommand::Ping, "ping"},
	{Subcommand::StartPhase, "start-phase"},
	{Subcommand::EndPhase, "end-phase"},
	{Subcommand::Report, "report"},
	{Subcommand::Shutdown, "shutdown"},
}};

std::string subcommandToString(Subcommand s)
{
	for (const auto &[v, name] : subcommand_table)
	{
		if (v == s)
			return name;
	}

	return {};
}

std::optional<Subcommand> subcommandFromString(std::string_view s)
{
	for (const auto &[v, name] : subcommand_table)
	{
		if (s == name)
			return v;
	}

	return std::nullopt;
}

static void usage()
{
	const char usageText[] =
		"Usage: blastguardctl <subcommand> [options]\n"
		"\n"
		"Subcommands:\n"
		"  ping                                     - health check\n"
		"  start-phase <PID> <NAME>                 - register watched root pid\n"
		"  end-phase                                - finalise findings\n"
		"  report [--format <fmt>] [--fail-on <s>]  - render report (fmt: markdown|json)\n"
		"  shutdown                                 - stop the daemon\n";

	std::println("{}", usageText);

	std::exit(EXIT_FAILURE);
}

Args parseArgs(int argc, char *argv[])
{
	if (argc < 2)
		usage();

	const auto sub_opt = subcommandFromString(argv[1]);

	if (!sub_opt)
	{
		std::println(stderr, "unknown subcommand: {}", argv[1]);
		usage();
	}

	Args ret;
	ret.sub = *sub_opt;

	auto shift = [i = 2, argc, argv]() mutable -> std::string_view
	{
		if (i >= argc)
			return {};

		return argv[i++];
	};

	int pos_idx = 0;

	for (;;)
	{
		const std::string_view arg = shift();

		if (arg.empty())
			break;

		auto optionValue = [&shift](std::string_view a,
							   std::string_view name) -> std::optional<std::string_view>
		{
			if (a == name)
				return shift();

			if (a.starts_with(name) && a.size() > name.size() && a[name.size()] == '=')
				return a.substr(name.size() + 1);

			return std::nullopt;
		};

		if (auto value = optionValue(arg, "--format"))
		{
			if (value->empty())
			{
				std::println(stderr, "--format requires an argument");
				usage();
			}

			const auto f = formatFromString(*value);

			if (!f)
			{
				std::println(stderr, "invalid --format value: {}", *value);
				usage();
			}

			ret.format = *f;
		}
		else if (auto value = optionValue(arg, "--fail-on"))
		{
			if (value->empty())
			{
				std::println(stderr, "--fail-on requires an argument");
				usage();
			}

			const auto s = severityFromString(*value);

			if (!s)
			{
				std::println(stderr, "invalid --fail-on value: {}", *value);
				usage();
			}

			ret.fail_on = *s;
		}
		else if (!arg.starts_with("-"))
		{
			if (ret.sub == Subcommand::StartPhase)
			{
				if (pos_idx == 0)
					std::from_chars(arg.data(), arg.data() + arg.size(), ret.watch_pid);
				else if (pos_idx == 1)
					ret.phase = arg;
			}

			++pos_idx;
		}
	}

	return ret;
}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "common/proto.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

enum class Subcommand : std::uint8_t
{
	Ping,
	StartPhase,
	EndPhase,
	Report,
	Shutdown,
};

std::string subcommandToString(Subcommand s);
std::optional<Subcommand> subcommandFromString(std::string_view s);

struct Args
{
	Subcommand sub = Subcommand::Ping;

	std::uint32_t watch_pid = 0;
	std::string_view phase;

	Format format = Format::Markdown;
	Severity fail_on = Severity::None;
};

Args parseArgs(int argc, char *argv[]);

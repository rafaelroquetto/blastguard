/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

enum class Mode : std::uint8_t
{
	Audit,
	Enforce,
};

std::string modeToString(Mode m);
std::optional<Mode> modeFromString(std::string_view s);

struct Args
{
	Mode mode = Mode::Audit;
	std::vector<std::string> allowed_hosts;
	bool verbose = false;
};

Args parseArgs(int argc, char *argv[]);

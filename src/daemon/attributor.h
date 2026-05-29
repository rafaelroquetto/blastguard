/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

class Attributor
{
public:
	Attributor() = default;

	std::optional<std::string> packageFromCwd(std::string_view cwd) const;
	std::optional<std::string> packageFromPath(std::string_view path) const;
	std::optional<std::string> phaseFromEnv(const char *env, std::uint32_t env_len) const;
};

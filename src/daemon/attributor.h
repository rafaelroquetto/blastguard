/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>

class Attributor
{
public:
	Attributor() = default;

	std::optional<std::string> packageFromCwd(const std::string &cwd) const;
	std::optional<std::string> phaseFromEnv(const char *env, std::uint32_t env_len) const;
};

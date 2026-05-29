/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "attributor.h"

#include <cstring>
#include <filesystem>
#include <string_view>
#include <vector>

std::optional<std::string> Attributor::packageFromCwd(std::string_view cwd) const
{
	return packageFromPath(cwd);
}

std::optional<std::string> Attributor::packageFromPath(std::string_view path) const
{
	if (path.empty())
		return std::nullopt;

	std::vector<std::string> parts;
	const std::filesystem::path p(path);

	for (const auto &c : p)
		parts.push_back(c.string());

	int last_nm = -1;

	for (int i = static_cast<int>(parts.size()) - 1; i >= 0; --i)
	{
		if (parts[i] == "node_modules")
		{
			last_nm = i;
			break;
		}
	}

	if (last_nm < 0)
		return std::nullopt;

	const int next_idx = last_nm + 1;

	if (next_idx >= static_cast<int>(parts.size()))
		return std::nullopt;

	const std::string &next = parts[next_idx];

	if (next == ".pnpm")
	{
		for (int j = next_idx + 1; j + 1 < static_cast<int>(parts.size()); ++j)
		{
			if (parts[j] == "node_modules")
				return parts[j + 1];
		}

		return std::nullopt;
	}

	if (next.starts_with("@") && next_idx + 1 < static_cast<int>(parts.size()))
		return next + "/" + parts[next_idx + 1];

	if (next.starts_with(".") || next.starts_with("_"))
		return std::nullopt;

	return next;
}

std::optional<std::string> Attributor::phaseFromEnv(const char *env, std::uint32_t env_len) const
{
	const std::string_view key = "npm_lifecycle_event=";
	std::uint32_t pos = 0;

	while (pos < env_len)
	{
		const std::size_t remaining = env_len - pos;
		const std::size_t entry_len = ::strnlen(env + pos, remaining);
		const std::string_view entry(env + pos, entry_len);

		if (entry.starts_with(key))
			return std::string(entry.substr(key.size()));

		pos += entry_len + 1;
	}

	return std::nullopt;
}

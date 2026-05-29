/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "common/proto.h"
#include "rules.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

struct Finding
{
	rules::RuleId rule_id = rules::RuleId::UnexpectedBinary;
	Severity severity = Severity::Low;
	std::uint32_t pid = 0;
	std::string package;
	std::string lifecycle_phase;
	std::string message;
	std::vector<std::string> tokens_exposed;
	bool blocked = false;
};

class Session
{
public:
	Session() = default;

	void startPhase(std::string name, std::uint32_t watched_pid);
	void endPhase();
	void reset();
	bool isActive() const;
	std::string_view phaseName() const;
	std::uint32_t watchedPid() const;

	void addFinding(Finding f);
	std::vector<Finding> findings() const;

	std::uint32_t internPackage(const std::string &name);
	std::string_view packageName(std::uint32_t id) const;

	void markExtracted(std::string name);
	std::vector<std::string> extractedPackages() const;
	bool packageHadExec(std::string_view name) const;

	void setPidPackage(std::uint32_t pid, std::uint32_t package_id);
	std::uint32_t pidPackage(std::uint32_t pid) const;

	void setPidTokens(std::uint32_t pid, std::uint32_t token_mask);
	std::uint32_t pidTokens(std::uint32_t pid) const;

	Severity maxSeverity() const;

private:
	std::string m_phaseName;
	std::uint32_t m_watchedPid = 0;
	bool m_active = false;

	std::vector<Finding> m_findings;

	struct StringHash
	{
		using is_transparent = void;

		std::size_t operator()(std::string_view v) const noexcept
		{
			return std::hash<std::string_view>{}(v);
		}
	};

	std::unordered_map<std::string, std::uint32_t, StringHash, std::equal_to<>> m_packageIdByName;
	std::vector<std::string> m_packageNameById;

	std::unordered_map<std::uint32_t, std::uint32_t> m_pidPackage;
	std::unordered_map<std::uint32_t, std::uint32_t> m_pidTokens;

	std::vector<std::string> m_extractedPackages;
};

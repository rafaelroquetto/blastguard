/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "session.h"

#include <algorithm>
#include <utility>

void Session::startPhase(std::string name, std::uint32_t watched_pid)
{
	m_phaseName = std::move(name);
	m_watchedPid = watched_pid;
	m_active = true;
}

void Session::endPhase()
{
	m_active = false;
}

void Session::reset()
{
	m_phaseName.clear();
	m_watchedPid = 0;
	m_active = false;
	m_findings.clear();
	m_packageIdByName.clear();
	m_packageNameById.clear();
	m_pidPackage.clear();
	m_pidTokens.clear();
	m_extractedPackages.clear();
}

bool Session::isActive() const
{
	return m_active;
}

std::string_view Session::phaseName() const
{
	return m_phaseName;
}

std::uint32_t Session::watchedPid() const
{
	return m_watchedPid;
}

void Session::addFinding(Finding f)
{
	m_findings.push_back(std::move(f));
}

std::vector<Finding> Session::findings() const
{
	return m_findings;
}

std::uint32_t Session::internPackage(const std::string &name)
{
	if (auto it = m_packageIdByName.find(name); it != m_packageIdByName.end())
		return it->second;

	const std::uint32_t id = static_cast<std::uint32_t>(m_packageNameById.size()) + 1;

	m_packageNameById.push_back(name);
	m_packageIdByName.emplace(name, id);

	return id;
}

std::string_view Session::packageName(std::uint32_t id) const
{
	if (id == 0 || id > m_packageNameById.size())
		return {};

	return m_packageNameById[id - 1];
}

void Session::markExtracted(std::string name)
{
	if (std::ranges::find(m_extractedPackages, name) == m_extractedPackages.end())
		m_extractedPackages.push_back(std::move(name));
}

std::vector<std::string> Session::extractedPackages() const
{
	return m_extractedPackages;
}

bool Session::packageHadExec(std::string_view name) const
{
	return m_packageIdByName.contains(name);
}

void Session::setPidPackage(std::uint32_t pid, std::uint32_t package_id)
{
	m_pidPackage[pid] = package_id;
}

std::uint32_t Session::pidPackage(std::uint32_t pid) const
{
	if (auto it = m_pidPackage.find(pid); it != m_pidPackage.end())
		return it->second;

	return 0;
}

void Session::setPidTokens(std::uint32_t pid, std::uint32_t token_mask)
{
	m_pidTokens[pid] = token_mask;
}

std::uint32_t Session::pidTokens(std::uint32_t pid) const
{
	if (auto it = m_pidTokens.find(pid); it != m_pidTokens.end())
		return it->second;

	return 0;
}

Severity Session::maxSeverity() const
{
	Severity max = Severity::None;

	for (const auto &f : m_findings)
	{
		if (static_cast<int>(f.severity) > static_cast<int>(max))
			max = f.severity;
	}

	return max;
}

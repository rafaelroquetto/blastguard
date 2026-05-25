/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "bpf/events.h"
#include "common/net.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

class Session;

namespace rules
{

enum class RuleId : std::uint8_t
{
	UnexpectedBinary = 1,
	NonAllowlistedHost,
	TokenBearingDownloader,
	SensitiveFileRead,
	SensitiveFileWrite,
};

struct RuleInfo
{
	RuleId id;
	std::string_view code;
	std::string_view title;
};

inline constexpr std::array<RuleInfo, 5> rule_table = {{
	{RuleId::UnexpectedBinary, "R1", "lifecycle-spawned-unexpected-binary"},
	{RuleId::NonAllowlistedHost, "R2", "outbound-to-non-allowlisted-host"},
	{RuleId::TokenBearingDownloader, "R3", "secret-bearing-lifecycle-spawned-downloader"},
	{RuleId::SensitiveFileRead, "R4", "sensitive-file-read-by-descendant"},
	{RuleId::SensitiveFileWrite, "R5", "sensitive-file-modified-during-install"},
}};

constexpr RuleInfo ruleInfo(RuleId id)
{
	for (const auto &r : rule_table)
	{
		if (r.id == id)
			return r;
	}

	return rule_table.front();
}

class Allowlist
{
public:
	void addHost(std::string_view host);

	bool contains(IPv4 addr_n) const;
	bool contains(const IPv6 &addr) const;

	std::vector<IPv6> addrs() const;

private:
	std::vector<IPv6> m_addrs;
};

void onExec(const event_exec *e, std::string_view argv, std::uint32_t token_mask,
	std::uint32_t package_id, std::string_view package_name, std::string_view phase,
	Session &session);

void onConnect(const event_connect *e, std::string_view ip, const Allowlist &allowlist,
	std::uint32_t package_id, std::string_view package_name, Session &session);

void onOpen(const event_open *e, std::string_view path, std::uint32_t package_id,
	std::string_view package_name, Session &session);

}

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "rules.h"

#include "common/tokens.h"
#include "session.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace rules
{

constexpr std::array<std::string_view, 11> dangerous_basenames = {
	"curl",
	"wget",
	"python",
	"python3",
	"perl",
	"ruby",
	"base64",
	"openssl",
	"nc",
	"ncat",
	"socat",
};

constexpr std::array<std::string_view, 4> lifecycle_phases = {
	"preinstall",
	"install",
	"postinstall",
	"prepare",
};

static bool isDangerousBasename(std::string_view comm)
{
	return std::any_of(dangerous_basenames.begin(), dangerous_basenames.end(),
		[&](std::string_view s)
	{
		return s == comm;
	});
}

static bool isLifecyclePhase(std::string_view phase)
{
	return std::any_of(lifecycle_phases.begin(), lifecycle_phases.end(), [&](std::string_view s)
	{
		return s == phase;
	});
}

static std::vector<std::string> tokensFromMask(std::uint32_t mask)
{
	std::vector<std::string> out;

	for (const auto &t : token_table)
	{
		if (mask & t.bit)
			out.emplace_back(t.name);
	}

	return out;
}

static bool hasNonGithubToken(std::uint32_t mask)
{
	return (mask & ~token_bit_github_token) != 0;
}

static bool isPersistenceVector(std::string_view path)
{
	static constexpr std::array<std::string_view, 6> patterns = {
		"/.npmrc",
		"/.gitconfig",
		"/.ssh/authorized_keys",
		"/.github/workflows",
		"/.git/hooks/",
		"/.bashrc",
	};

	return std::any_of(patterns.begin(), patterns.end(), [&](std::string_view p)
	{
		return path.find(p) != std::string_view::npos;
	});
}

static bool isCredentialFile(std::string_view path)
{
	static constexpr std::array<std::string_view, 5> patterns = {
		"/.npmrc",
		"/.aws/credentials",
		"/.ssh/",
		"/var/run/secrets",
		"/.docker/config.json",
	};

	return std::any_of(patterns.begin(), patterns.end(), [&](std::string_view p)
	{
		return path.find(p) != std::string_view::npos;
	});
}

static std::string formatTokenList(const std::vector<std::string> &tokens)
{
	std::string out;

	for (const auto &t : tokens)
	{
		if (!out.empty())
			out += ", ";

		out += "`";
		out += t;
		out += "`";
	}

	return out;
}

static IPv6 mapV4(IPv4 addr_n)
{
	IPv6 key{};
	key[10] = 0xff;
	key[11] = 0xff;
	std::memcpy(key.data() + 12, &addr_n, 4);

	return key;
}

void Allowlist::addHost(std::string_view host)
{
	std::string h(host);

	struct addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *res = nullptr;

	if (::getaddrinfo(h.c_str(), nullptr, &hints, &res) != 0)
		return;

	for (auto *p = res; p; p = p->ai_next)
	{
		IPv6 addr{};

		if (p->ai_family == AF_INET)
		{
			auto *sin = reinterpret_cast<sockaddr_in *>(p->ai_addr);
			addr = mapV4(sin->sin_addr.s_addr);
		}
		else if (p->ai_family == AF_INET6)
		{
			auto *sin6 = reinterpret_cast<sockaddr_in6 *>(p->ai_addr);
			std::memcpy(addr.data(), &sin6->sin6_addr, 16);
		}
		else
		{
			continue;
		}

		if (std::ranges::find(m_addrs, addr) == m_addrs.end())
			m_addrs.push_back(addr);
	}

	::freeaddrinfo(res);
}

bool Allowlist::contains(IPv4 addr_n) const
{
	return contains(mapV4(addr_n));
}

bool Allowlist::contains(const IPv6 &addr) const
{
	return std::ranges::find(m_addrs, addr) != m_addrs.end();
}

std::vector<IPv6> Allowlist::addrs() const
{
	return m_addrs;
}

void onExec(const event_exec *e, std::string_view argv, std::uint32_t token_mask,
	std::uint32_t package_id, std::string_view package_name, std::string_view phase,
	Session &session)
{
	if (!session.isActive() || package_id == 0)
		return;

	const std::string_view comm{e->comm, ::strnlen(e->comm, sizeof(e->comm))};

	if (!isDangerousBasename(comm))
		return;

	if (!isLifecyclePhase(phase))
		return;

	auto tokens = tokensFromMask(token_mask);

	if (hasNonGithubToken(token_mask))
	{
		const std::string token_list = formatTokenList(tokens);

		Finding f{};
		f.rule_id = RuleId::TokenBearingDownloader;
		f.severity = Severity::High;
		f.pid = e->hdr.pid;
		f.package = std::string(package_name);
		f.lifecycle_phase = std::string(phase);
		f.tokens_exposed = std::move(tokens);
		f.message = std::format("Lifecycle script for `{}` ({}) had {} in its environment when it "
								"ran `{}` (argv: `{}`). Rotate these.",
			package_name, phase, token_list, comm, argv);

		session.addFinding(std::move(f));
		return;
	}

	Finding f{};
	f.rule_id = RuleId::UnexpectedBinary;
	f.severity = Severity::High;
	f.pid = e->hdr.pid;
	f.package = std::string(package_name);
	f.lifecycle_phase = std::string(phase);
	f.message = std::format("Package `{}` ({}) spawned `{}` (argv: `{}`).", package_name, phase,
		comm, argv);

	session.addFinding(std::move(f));
}

void onConnect(const event_connect *e, std::string_view ip, const Allowlist &allowlist,
	std::uint32_t package_id, std::string_view package_name, Session &session)
{
	if (!session.isActive() || package_id == 0)
		return;

	IPv6 addr;
	std::memcpy(addr.data(), e->addr, 16);

	if (allowlist.contains(addr))
		return;

	const std::uint32_t pid_tokens = session.pidTokens(e->hdr.pid);
	const bool has_tokens = hasNonGithubToken(pid_tokens);

	Finding f{};
	f.rule_id = RuleId::NonAllowlistedHost;
	f.severity = has_tokens ? Severity::High : Severity::Medium;
	f.pid = e->hdr.pid;
	f.package = std::string(package_name);
	f.tokens_exposed = tokensFromMask(pid_tokens);
	f.blocked = e->blocked != 0;
	f.message = std::format("Connection to `{}:{}` from `{}` (pid {}){}", ip, e->port, package_name,
		e->hdr.pid, f.blocked ? " — blocked." : ".");

	session.addFinding(std::move(f));
}

void onOpen(const event_open *e, std::string_view path, std::uint32_t package_id,
	std::string_view package_name, Session &session)
{
	if (!session.isActive() || package_id == 0)
		return;

	const int access_mode = e->flags & 0x3;
	const bool writable = (access_mode != 0) || (e->flags & 0100) || (e->flags & 02000);

	if (writable && isPersistenceVector(path))
	{
		Finding f{};
		f.rule_id = RuleId::SensitiveFileWrite;
		f.severity = Severity::High;
		f.pid = e->hdr.pid;
		f.package = std::string(package_name);
		f.message = std::format(
			"Process (pid {}, from `{}`) modified `{}` during install. Persistence vector.",
			e->hdr.pid, package_name, path);

		session.addFinding(std::move(f));
		return;
	}

	if (!writable && isCredentialFile(path))
	{
		Finding f{};
		f.rule_id = RuleId::SensitiveFileRead;
		f.severity = Severity::High;
		f.pid = e->hdr.pid;
		f.package = std::string(package_name);
		f.message =
			std::format("Process (pid {}, from `{}`) read `{}`.", e->hdr.pid, package_name, path);

		session.addFinding(std::move(f));
	}
}

}

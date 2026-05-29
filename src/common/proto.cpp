/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "proto.h"

#include "common/io.h"
#include "common/uniquefd.h"

#include <array>
#include <cerrno>
#include <charconv>
#include <cstddef>
#include <cstring>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <tuple>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

constexpr std::array<std::tuple<Format, const char *>, 2> format_table = {{
	{Format::Markdown, "markdown"},
	{Format::Json, "json"},
}};

constexpr std::array<std::tuple<Severity, const char *>, 4> severity_table = {{
	{Severity::None, "none"},
	{Severity::Low, "low"},
	{Severity::Medium, "medium"},
	{Severity::High, "high"},
}};

std::string formatToString(Format f)
{
	for (const auto &[v, name] : format_table)
	{
		if (v == f)
			return name;
	}

	return {};
}

std::optional<Format> formatFromString(std::string_view s)
{
	for (const auto &[v, name] : format_table)
	{
		if (s == name)
			return v;
	}

	return std::nullopt;
}

std::string severityToString(Severity s)
{
	for (const auto &[v, name] : severity_table)
	{
		if (v == s)
			return name;
	}

	return {};
}

std::optional<Severity> severityFromString(std::string_view s)
{
	for (const auto &[v, name] : severity_table)
	{
		if (s == name)
			return v;
	}

	return std::nullopt;
}

static constexpr std::string_view cmd_ping = "PING";
static constexpr std::string_view cmd_start_phase = "START-PHASE";
static constexpr std::string_view cmd_end_phase = "END-PHASE";
static constexpr std::string_view cmd_report = "REPORT";
static constexpr std::string_view cmd_shutdown = "SHUTDOWN";

static constexpr std::string_view reply_pong = "PONG";
static constexpr std::string_view reply_ok = "OK";
static constexpr std::string_view reply_error = "ERR";

std::string encode(const PingRequest &)
{
	return std::string(cmd_ping);
}

std::string encode(const StartPhaseRequest &r)
{
	return std::format("{} {} {}", cmd_start_phase, r.pid, r.phase);
}

std::string encode(const EndPhaseRequest &)
{
	return std::string(cmd_end_phase);
}

std::string encode(const ReportRequest &r)
{
	return std::format("{} {}", cmd_report, formatToString(r.format));
}

std::string encode(const ShutdownRequest &)
{
	return std::string(cmd_shutdown);
}

std::string encode(const PongResponse &)
{
	return std::string(reply_pong);
}

std::string encode(const OkResponse &)
{
	return std::string(reply_ok);
}

std::string encode(const Error &r)
{
	if (r.reason.empty())
		return std::string(reply_error);

	return std::format("{} {}", reply_error, r.reason);
}

std::optional<Error> decodeError(std::string_view raw)
{
	const std::size_t nl = raw.find('\n');
	const std::string_view first = nl == std::string_view::npos ? raw : raw.substr(0, nl);

	if (first != reply_error && !first.starts_with(std::string(reply_error) + " "))
		return std::nullopt;

	std::string_view reason = first.substr(reply_error.size());

	while (!reason.empty() && reason.front() == ' ')
		reason.remove_prefix(1);

	if (reason.empty())
		return Error{"request rejected"};

	return Error{std::string(reason)};
}

std::string encode(const ReportResponse &r)
{
	return std::format("MAX_SEVERITY: {}\n{}", severityToString(r.max_severity), r.body);
}

static std::string_view nextToken(std::string_view &rest)
{
	const std::size_t sp = rest.find(' ');

	if (sp == std::string_view::npos)
	{
		const std::string_view tok = rest;
		rest = {};

		return tok;
	}

	const std::string_view tok = rest.substr(0, sp);
	rest = rest.substr(sp + 1);

	return tok;
}

std::optional<Request> decodeRequest(std::string_view line)
{
	std::string_view rest = line;
	const std::string_view cmd = nextToken(rest);

	if (cmd == cmd_ping)
		return PingRequest{};

	if (cmd == cmd_end_phase)
		return EndPhaseRequest{};

	if (cmd == cmd_shutdown)
		return ShutdownRequest{};

	if (cmd == cmd_start_phase)
	{
		const std::string_view pid_str = nextToken(rest);

		std::uint32_t pid = 0;
		std::from_chars(pid_str.data(), pid_str.data() + pid_str.size(), pid);

		if (pid == 0 || rest.empty())
			return std::nullopt;

		return StartPhaseRequest{.pid = pid, .phase = std::string(rest)};
	}

	if (cmd == cmd_report)
	{
		const auto fmt = formatFromString(rest.empty() ? "markdown" : rest);

		if (!fmt)
			return std::nullopt;

		return ReportRequest{.format = *fmt};
	}

	return std::nullopt;
}

static std::string_view trimTrailingNewlines(std::string_view s)
{
	while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
		s.remove_suffix(1);

	return s;
}

template <> std::optional<PongResponse> decodeResponse<PongResponse>(std::string_view raw)
{
	if (trimTrailingNewlines(raw) != reply_pong)
		return std::nullopt;

	return PongResponse{};
}

template <> std::optional<OkResponse> decodeResponse<OkResponse>(std::string_view raw)
{
	if (trimTrailingNewlines(raw) != reply_ok)
		return std::nullopt;

	return OkResponse{};
}

template <> std::optional<ReportResponse> decodeResponse<ReportResponse>(std::string_view raw)
{
	const std::size_t nl = raw.find('\n');

	if (nl == std::string_view::npos)
		return std::nullopt;

	const std::string_view header = raw.substr(0, nl);
	const std::string_view body = raw.substr(nl + 1);

	const std::size_t colon = header.find(':');

	if (colon == std::string_view::npos)
		return std::nullopt;

	std::string_view sev_str = header.substr(colon + 1);

	while (!sev_str.empty() && sev_str.front() == ' ')
		sev_str.remove_prefix(1);

	const Severity sev = severityFromString(sev_str).value_or(Severity::None);

	return ReportResponse{.max_severity = sev, .body = std::string(body)};
}

std::string sendRaw(std::string_view wire)
{
	UniqueFD fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));

	if (!fd)
	{
		std::println(stderr, "socket: {}", std::strerror(errno));
		return {};
	}

	sockaddr_un addr{};
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	std::memcpy(addr.sun_path + 1, socket_name.data(), socket_name.size());

	const socklen_t addrlen = offsetof(sockaddr_un, sun_path) + 1 + socket_name.size();

	if (::connect(fd.handle(), reinterpret_cast<sockaddr *>(&addr), addrlen) < 0)
	{
		std::println(stderr, "connect @{}: {}", socket_name, std::strerror(errno));
		return {};
	}

	std::string buf(wire);
	buf.push_back('\n');

	writeAll(fd.handle(), buf);
	::shutdown(fd.handle(), SHUT_WR);

	std::string reply;
	readAll(fd.handle(), reply, max_line * 4);

	return reply;
}

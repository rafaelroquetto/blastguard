/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

constexpr std::string_view socket_name = "blastguard";
constexpr std::size_t max_line = 64 * 1024;

enum class Format : std::uint8_t
{
	Markdown,
	Json,
};

enum class Severity : std::uint8_t
{
	None,
	Low,
	Medium,
	High,
};

std::string formatToString(Format f);
std::optional<Format> formatFromString(std::string_view s);

std::string severityToString(Severity s);
std::optional<Severity> severityFromString(std::string_view s);

struct PongResponse
{
};

struct OkResponse
{
};

struct Error
{
	std::string reason;
};

struct ReportResponse
{
	Severity max_severity = Severity::None;
	std::string body;
};

struct PingRequest
{
	using Response = PongResponse;
};

struct StartPhaseRequest
{
	using Response = OkResponse;
	std::uint32_t pid = 0;
	std::string phase;
};

struct EndPhaseRequest
{
	using Response = OkResponse;
};

struct ReportRequest
{
	using Response = ReportResponse;
	Format format = Format::Markdown;
};

struct ShutdownRequest
{
	using Response = OkResponse;
};

using Request =
	std::variant<PingRequest, StartPhaseRequest, EndPhaseRequest, ReportRequest, ShutdownRequest>;

template <typename T>
concept RequestType = requires(const T &req) { typename T::Response; };

std::string encode(const PingRequest &);
std::string encode(const StartPhaseRequest &);
std::string encode(const EndPhaseRequest &);
std::string encode(const ReportRequest &);
std::string encode(const ShutdownRequest &);

std::string encode(const PongResponse &);
std::string encode(const OkResponse &);
std::string encode(const Error &);
std::string encode(const ReportResponse &);

std::optional<Request> decodeRequest(std::string_view line);

template <typename R> std::optional<R> decodeResponse(std::string_view raw);

template <> std::optional<PongResponse> decodeResponse<PongResponse>(std::string_view raw);

template <> std::optional<OkResponse> decodeResponse<OkResponse>(std::string_view raw);

template <> std::optional<ReportResponse> decodeResponse<ReportResponse>(std::string_view raw);

std::string sendRaw(std::string_view wire);

std::optional<Error> decodeError(std::string_view raw);

template <RequestType Req> std::expected<typename Req::Response, Error> sendCommand(const Req &req)
{
	const std::string raw = sendRaw(encode(req));

	if (raw.empty())
		return std::unexpected(Error{"no response from daemon"});

	if (auto err = decodeError(raw))
		return std::unexpected(std::move(*err));

	auto resp = decodeResponse<typename Req::Response>(raw);

	if (!resp)
		return std::unexpected(Error{"malformed response from daemon"});

	return *resp;
}

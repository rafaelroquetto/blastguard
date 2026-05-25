/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstdint>
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

struct ErrorResponse
{
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
std::string encode(const ErrorResponse &);
std::string encode(const ReportResponse &);

std::optional<Request> decodeRequest(std::string_view line);

template <typename R> std::optional<R> decodeResponse(std::string_view raw);

template <> std::optional<PongResponse> decodeResponse<PongResponse>(std::string_view raw);

template <> std::optional<OkResponse> decodeResponse<OkResponse>(std::string_view raw);

template <> std::optional<ReportResponse> decodeResponse<ReportResponse>(std::string_view raw);

std::string sendRaw(std::string_view wire);

template <RequestType Req> std::optional<typename Req::Response> sendCommand(const Req &req)
{
	return decodeResponse<typename Req::Response>(sendRaw(encode(req)));
}

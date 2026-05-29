/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "args.h"
#include "common/proto.h"

#include <print>
#include <string>
#include <string_view>

static int doPing()
{
	const auto resp = sendCommand(PingRequest{});

	if (!resp)
	{
		std::println(stderr, "ping: {}", resp.error().reason);
		return 1;
	}

	std::println("PONG");

	return 0;
}

static int doStartPhase(const Args &args)
{
	if (args.watch_pid == 0 || args.phase.empty())
	{
		std::println(stderr, "usage: blastguardctl start-phase <PID> <NAME>");
		return 2;
	}

	const auto resp =
		sendCommand(StartPhaseRequest{.pid = args.watch_pid, .phase = std::string(args.phase)});

	if (!resp)
	{
		std::println(stderr, "start-phase: {}", resp.error().reason);
		return 1;
	}

	std::println("OK");

	return 0;
}

static int doEndPhase()
{
	const auto resp = sendCommand(EndPhaseRequest{});

	if (!resp)
	{
		std::println(stderr, "end-phase: {}", resp.error().reason);
		return 1;
	}

	std::println("OK");

	return 0;
}

static int doReport(const Args &args)
{
	const auto resp = sendCommand(ReportRequest{.format = args.format});

	if (!resp)
	{
		std::println(stderr, "report: {}", resp.error().reason);
		return 1;
	}

	std::print("{}", resp->body);

	return args.fail_on != Severity::None && resp->max_severity >= args.fail_on ? 1 : 0;
}

static int doShutdown()
{
	const auto resp = sendCommand(ShutdownRequest{});

	if (!resp)
	{
		std::println(stderr, "shutdown: {}", resp.error().reason);
		return 1;
	}

	std::println("OK");

	return 0;
}

int main(int argc, char *argv[])
{
	const Args args = parseArgs(argc, argv);

	switch (args.sub)
	{
	case Subcommand::Ping:
		return doPing();
	case Subcommand::StartPhase:
		return doStartPhase(args);
	case Subcommand::EndPhase:
		return doEndPhase();
	case Subcommand::Report:
		return doReport(args);
	case Subcommand::Shutdown:
		return doShutdown();
	}

	return 2;
}

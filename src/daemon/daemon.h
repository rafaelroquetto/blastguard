/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "args.h"
#include "attributor.h"
#include "bpf/events.h"
#include "common/uniquefd.h"
#include "ebpfmanager.h"
#include "ipcserver.h"
#include "rules.h"
#include "session.h"

#include <expected>
#include <span>

class Daemon
{
public:
	explicit Daemon(const Args &args);

	bool init();
	int exec();

private:
	void setupHandlers();
	bool setupEpoll();

	void onEvent(std::span<const std::byte> data);

	template <typename T>
	void dispatch(std::span<const std::byte> data, void (Daemon::*handler)(const T &));

	void onForkEvent(const event_fork &e);
	void onConnectEvent(const event_connect &e);
	void onOpenEvent(const event_open &e);
	void onExecEvent(const event_exec &e);

	std::expected<PongResponse, Error> onPingRequest(const PingRequest &);
	std::expected<OkResponse, Error> onStartPhaseRequest(const StartPhaseRequest &r);
	std::expected<OkResponse, Error> onEndPhaseRequest(const EndPhaseRequest &);
	std::expected<ReportResponse, Error> onReportRequest(const ReportRequest &r);
	std::expected<OkResponse, Error> onShutdownRequest(const ShutdownRequest &);

	Args m_args;
	EBPFManager m_mgr;
	IPCServer m_ipc;
	Attributor m_attributor;
	Session m_session;
	rules::Allowlist m_allowlist;
	UniqueFD m_epollFd;
};

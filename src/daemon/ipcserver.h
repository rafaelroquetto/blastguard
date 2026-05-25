/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "common/proto.h"
#include "common/uniquefd.h"

#include <exception>
#include <functional>
#include <tuple>
#include <utility>

class RejectedRequest : public std::exception
{
public:
	const char *what() const noexcept override
	{
		return "request rejected";
	}
};

class IPCServer
{
public:
	IPCServer() = default;

	bool init();

	int listenFd() const;
	void acceptOnce();

	template <RequestType Req, typename Fn> void setHandler(Fn fn)
	{
		std::get<HandlerFor<Req>>(m_handlers) = std::move(fn);
	}

private:
	void handleClient(int client_fd);

	template <typename Req>
	using HandlerFor = std::move_only_function<typename Req::Response(const Req &)>;

	UniqueFD m_listenFd;

	std::tuple<HandlerFor<PingRequest>, HandlerFor<StartPhaseRequest>, HandlerFor<EndPhaseRequest>,
		HandlerFor<ReportRequest>, HandlerFor<ShutdownRequest>>
		m_handlers;
};

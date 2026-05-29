/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "ipcserver.h"

#include "common/io.h"
#include "common/proto.h"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <print>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void writeWire(int fd, std::string_view s)
{
	std::string buf(s);
	buf.push_back('\n');

	writeAll(fd, buf);
}

bool IPCServer::init()
{
	static_assert(1 + socket_name.size() <= sizeof(sockaddr_un{}.sun_path));

	UniqueFD fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));

	if (!fd)
	{
		std::println(stderr, "socket: {}", std::strerror(errno));
		return false;
	}

	sockaddr_un addr{};
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = '\0';
	std::memcpy(addr.sun_path + 1, socket_name.data(), socket_name.size());

	const socklen_t addrlen = offsetof(sockaddr_un, sun_path) + 1 + socket_name.size();

	if (::bind(fd.handle(), reinterpret_cast<sockaddr *>(&addr), addrlen) < 0)
	{
		std::println(stderr, "bind: {}", std::strerror(errno));
		return false;
	}

	if (::listen(fd.handle(), 8) < 0)
	{
		std::println(stderr, "listen: {}", std::strerror(errno));
		return false;
	}

	m_listenFd = std::move(fd);

	return true;
}

int IPCServer::listenFd() const
{
	return m_listenFd.handle();
}

void IPCServer::acceptOnce()
{
	const int raw = ::accept4(m_listenFd.handle(), nullptr, nullptr, SOCK_CLOEXEC);

	if (raw < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return;

		std::println(stderr, "accept4: {}", std::strerror(errno));
		return;
	}

	UniqueFD client(raw);

	handleClient(client.handle());
}

void IPCServer::handleClient(int client_fd)
{
	const std::string line = readLine(client_fd, max_line);
	const auto req = decodeRequest(line);

	if (!req)
	{
		writeWire(client_fd, encode(Error{"malformed request"}));
		return;
	}

	std::visit([this, client_fd](const auto &r)
	{
		using Req = std::decay_t<decltype(r)>;
		auto &handler = std::get<HandlerFor<Req>>(m_handlers);

		if (!handler)
		{
			writeWire(client_fd, encode(Error{"no handler registered"}));
			return;
		}

		const auto resp = handler(r);

		if (resp)
			writeWire(client_fd, encode(*resp));
		else
			writeWire(client_fd, encode(resp.error()));
	}, *req);
}

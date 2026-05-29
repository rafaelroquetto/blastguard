/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "daemon.h"

#include "common/tokens.h"
#include "report.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <iterator>
#include <print>
#include <span>
#include <string>
#include <string_view>

#include <arpa/inet.h>
#include <limits.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static std::uint32_t scanEnvForTokens(const char *buf, std::uint32_t len)
{
	std::uint32_t mask = 0;
	std::uint32_t pos = 0;

	while (pos < len)
	{
		const std::size_t remaining = len - pos;
		const std::size_t entry_len = ::strnlen(buf + pos, remaining);
		const std::string_view entry_view{buf + pos, entry_len};

		for (const auto &t : token_table)
		{
			if (entry_view.starts_with(t.prefix))
				mask |= t.bit;
		}

		pos += entry_len + 1;
	}

	return mask;
}

static std::string formatArgv(const char *buf, std::uint32_t len)
{
	std::string out;
	out.reserve(len);

	bool first = true;
	std::uint32_t pos = 0;

	while (pos < len)
	{
		const std::size_t remaining = len - pos;
		const std::size_t arg_len = ::strnlen(buf + pos, remaining);

		if (arg_len == 0 && pos > 0)
			break;

		if (!first)
			out.push_back(' ');

		first = false;
		out.append(buf + pos, arg_len);

		pos += arg_len + 1;
	}

	return out;
}

static std::string readCwd(std::uint32_t pid)
{
	char link[64];
	std::snprintf(link, sizeof(link), "/proc/%u/cwd", pid);

	char buf[PATH_MAX];
	const ssize_t n = ::readlink(link, buf, sizeof(buf));

	if (n <= 0)
		return {};

	return std::string(buf, static_cast<std::size_t>(n));
}

Daemon::Daemon(const Args &args) : m_args(args) {}

bool Daemon::init()
{
	if (!m_mgr.init())
		return false;

	for (const auto &h : m_args.allowed_hosts)
		m_allowlist.addHost(h);

	if (!m_mgr.setMode(m_args.mode))
		return false;

	const auto addrs = m_allowlist.addrs();

	if (m_args.mode == Mode::Enforce)
	{
		for (const auto &addr : addrs)
			m_mgr.addAllowedAddr(addr);
	}

	std::println(stderr, "blastguardd starting: mode={} allowlist_size={}",
		modeToString(m_args.mode), addrs.size());

	if (!m_ipc.init())
		return false;

	setupHandlers();

	return setupEpoll();
}

bool Daemon::setupEpoll()
{
	m_epollFd = UniqueFD(::epoll_create1(EPOLL_CLOEXEC));

	if (!m_epollFd)
	{
		std::println(stderr, "epoll_create1: {}", std::strerror(errno));
		return false;
	}

	epoll_event ev{};
	ev.events = EPOLLIN;

	ev.data.fd = m_ipc.listenFd();

	if (::epoll_ctl(m_epollFd.handle(), EPOLL_CTL_ADD, m_ipc.listenFd(), &ev) < 0)
	{
		std::println(stderr, "epoll_ctl ipc: {}", std::strerror(errno));
		return false;
	}

	ev.data.fd = m_mgr.ringBufFd();

	if (::epoll_ctl(m_epollFd.handle(), EPOLL_CTL_ADD, m_mgr.ringBufFd(), &ev) < 0)
	{
		std::println(stderr, "epoll_ctl ringbuf: {}", std::strerror(errno));
		return false;
	}

	return true;
}

void Daemon::setupHandlers()
{
	m_mgr.setEventCallback([this](std::span<const std::byte> data)
	{
		onEvent(data);
	});

	m_ipc.setHandler<PingRequest>([this](const PingRequest &r)
	{
		return onPingRequest(r);
	});

	m_ipc.setHandler<StartPhaseRequest>([this](const StartPhaseRequest &r)
	{
		return onStartPhaseRequest(r);
	});

	m_ipc.setHandler<EndPhaseRequest>([this](const EndPhaseRequest &r)
	{
		return onEndPhaseRequest(r);
	});

	m_ipc.setHandler<ReportRequest>([this](const ReportRequest &r)
	{
		return onReportRequest(r);
	});

	m_ipc.setHandler<ShutdownRequest>([this](const ShutdownRequest &r)
	{
		return onShutdownRequest(r);
	});
}

int Daemon::exec()
{
	while (true)
	{
		epoll_event events[2]; /* ebpf and ipc */
		const int n = ::epoll_wait(m_epollFd.handle(), events, std::size(events), -1);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			std::println(stderr, "epoll_wait: {}", std::strerror(errno));
			return 1;
		}

		for (int i = 0; i < n; ++i)
		{
			const int fd = events[i].data.fd;

			if (fd == m_ipc.listenFd())
				m_ipc.acceptOnce();
			else if (fd == m_mgr.ringBufFd())
				m_mgr.consume();
		}
	}

	return 0;
}

template <typename T>
void Daemon::dispatch(std::span<const std::byte> data, void (Daemon::*handler)(const T &))
{
	if (data.size() >= sizeof(T))
		(this->*handler)(*reinterpret_cast<const T *>(data.data()));
}

void Daemon::onEvent(std::span<const std::byte> data)
{
	if (data.size() < sizeof(event_hdr))
		return;

	const auto *h = reinterpret_cast<const event_hdr *>(data.data());

	switch (h->type)
	{
	case event_type_fork:
		dispatch(data, &Daemon::onForkEvent);
		return;
	case event_type_connect:
		dispatch(data, &Daemon::onConnectEvent);
		return;
	case event_type_open:
		dispatch(data, &Daemon::onOpenEvent);
		return;
	case event_type_exec:
		dispatch(data, &Daemon::onExecEvent);
		return;
	}
}

void Daemon::onForkEvent(const event_fork &e)
{
	std::uint32_t parent_pkg = m_session.pidPackage(e.hdr.pid);

	if (parent_pkg == 0 && e.package_id != 0)
		parent_pkg = e.package_id;

	if (parent_pkg == 0)
	{
		const std::string cwd = readCwd(e.hdr.pid);

		if (auto pkg = m_attributor.packageFromCwd(cwd))
		{
			parent_pkg = m_session.internPackage(*pkg);
			m_session.setPidPackage(e.hdr.pid, parent_pkg);
			m_mgr.setPackageForPid(e.hdr.pid, parent_pkg);
		}
	}

	m_session.setPidPackage(e.child_pid, parent_pkg);

	if (parent_pkg != 0)
		m_mgr.setPackageForPid(e.child_pid, parent_pkg);
}

void Daemon::onConnectEvent(const event_connect &e)
{
	char ipbuf[INET6_ADDRSTRLEN]{};

	if (e.family == 4)
		::inet_ntop(AF_INET, &e.addr[12], ipbuf, sizeof(ipbuf));
	else
		::inet_ntop(AF_INET6, e.addr, ipbuf, sizeof(ipbuf));

	std::uint32_t pkg_id = m_session.pidPackage(e.hdr.pid);

	if (pkg_id == 0 && e.package_id != 0)
		pkg_id = e.package_id;

	const std::string pkg_name = pkg_id != 0 ? std::string(m_session.packageName(pkg_id)) : "";

	rules::onConnect(&e, ipbuf, m_allowlist, pkg_id, pkg_name, m_session);

	if (m_args.verbose)
	{
		std::println("CONNECT pid={} addr={}:{} family=v{} package={} blocked={}", e.hdr.pid, ipbuf,
			e.port, e.family, pkg_name, e.blocked ? "yes" : "no");
	}
}

void Daemon::onOpenEvent(const event_open &e)
{
	std::size_t path_len = e.path_len;

	if (path_len > path_max)
		path_len = path_max;

	if (path_len > 0 && e.path[path_len - 1] == '\0')
		path_len--;

	const std::string_view path{e.path, path_len};

	std::uint32_t pkg_id = m_session.pidPackage(e.hdr.pid);

	if (pkg_id == 0 && e.package_id != 0)
		pkg_id = e.package_id;

	const std::string pkg_name = pkg_id != 0 ? std::string(m_session.packageName(pkg_id)) : "";

	rules::onOpen(&e, path, pkg_id, pkg_name, m_session);

	const int access_mode = e.flags & 0x3;
	const bool writable = (access_mode != 0) || (e.flags & 0100) || (e.flags & 02000);

	if (writable && m_session.isActive())
	{
		if (auto pkg = m_attributor.packageFromPath(path))
			m_session.markExtracted(*pkg);
	}

	if (m_args.verbose)
	{
		std::println("OPEN pid={} path={} flags=0x{:x} package={}", e.hdr.pid, path, e.flags,
			pkg_name);
	}
}

void Daemon::onExecEvent(const event_exec &e)
{
	const std::string argv_str = formatArgv(e.argv, e.argv_len);
	const std::uint32_t mask = scanEnvForTokens(e.env, e.env_len);

	m_session.setPidTokens(e.hdr.pid, mask);

	std::uint32_t pkg_id = m_session.pidPackage(e.hdr.pid);

	if (pkg_id == 0 && e.package_id != 0)
		pkg_id = e.package_id;

	if (pkg_id == 0)
	{
		const std::string cwd = readCwd(e.hdr.pid);

		if (auto pkg = m_attributor.packageFromCwd(cwd))
		{
			pkg_id = m_session.internPackage(*pkg);
			m_session.setPidPackage(e.hdr.pid, pkg_id);
			m_mgr.setPackageForPid(e.hdr.pid, pkg_id);
		}
	}

	const std::string pkg_name = pkg_id != 0 ? std::string(m_session.packageName(pkg_id)) : "";
	const auto phase_opt = m_attributor.phaseFromEnv(e.env, e.env_len);
	const std::string phase = phase_opt.value_or("");

	rules::onExec(&e, argv_str, mask, pkg_id, pkg_name, phase, m_session);

	if (m_args.verbose)
	{
		std::string tokens;

		for (const auto &t : token_table)
		{
			if (mask & t.bit)
			{
				if (!tokens.empty())
					tokens.push_back(',');

				tokens.append(t.name);
			}
		}

		std::println("EXEC pid={} ppid={} comm={} argv=[{}] tokens=[{}] package={} phase={}",
			e.hdr.pid, e.hdr.ppid, e.comm, argv_str, tokens, pkg_name, phase);
	}
}

std::expected<PongResponse, Error> Daemon::onPingRequest(const PingRequest &)
{
	return PongResponse{};
}

static bool pidExists(std::uint32_t pid)
{
	char path[64];
	std::snprintf(path, sizeof(path), "/proc/%u", pid);

	struct stat st;
	return ::stat(path, &st) == 0;
}

std::expected<OkResponse, Error> Daemon::onStartPhaseRequest(const StartPhaseRequest &r)
{
	if (m_session.isActive())
		return std::unexpected(
			Error{std::format("phase {} is already active", m_session.phaseName())});

	if (!pidExists(r.pid))
		return std::unexpected(Error{std::format("pid {} does not exist", r.pid)});

	m_session.reset();

	if (!m_mgr.trackPid(r.pid))
		return std::unexpected(Error{std::format("failed to track pid {}", r.pid)});

	m_session.startPhase(r.phase, r.pid);

	std::println(stderr, "phase started: pid={} phase={}", r.pid, r.phase);

	return OkResponse{};
}

std::expected<OkResponse, Error> Daemon::onEndPhaseRequest(const EndPhaseRequest &)
{
	m_session.endPhase();
	m_mgr.clearTrackedPids();

	std::println(stderr, "phase ended ({} finding(s))", m_session.findings().size());

	return OkResponse{};
}

std::expected<ReportResponse, Error> Daemon::onReportRequest(const ReportRequest &r)
{
	if (m_session.isActive())
		return std::unexpected(Error{std::format(
			"cannot generate report during an active phase ({})", m_session.phaseName())});

	return ReportResponse{
		.max_severity = m_session.maxSeverity(),
		.body = Report::render(m_session, r.format),
	};
}

std::expected<OkResponse, Error> Daemon::onShutdownRequest(const ShutdownRequest &)
{
	std::println(stderr, "shutdown requested");

	std::exit(0);
}

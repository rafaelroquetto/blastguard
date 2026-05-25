/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "ebpfmanager.h"

#include "args.h"
#include "bpf/events.h"

#include <cerrno>
#include <cstring>
#include <print>
#include <utility>

#include <bpf/bpf.h>
#include <fcntl.h>
#include <unistd.h>

int sampleCallback(void *ctx, void *data, std::size_t size)
{
	auto *self = static_cast<EBPFManager *>(ctx);

	return self->handleEvent(
		std::span<const std::byte>{static_cast<const std::byte *>(data), size});
}

bool EBPFManager::init()
{
	struct blastguard_bpf *skel = blastguard_bpf__open_and_load();

	if (!skel)
	{
		std::println(stderr, "blastguard_bpf__open_and_load failed");
		return false;
	}

	m_skel.reset(skel);

	struct bpf_program *tp_progs[] = {
		m_skel->progs.on_fork,
		m_skel->progs.on_exit,
		m_skel->progs.on_exec,
		m_skel->progs.on_openat,
		m_skel->progs.on_openat2,
	};

	for (struct bpf_program *prog : tp_progs)
	{
		struct bpf_link *link = bpf_program__attach(prog);

		if (!link)
		{
			std::println(stderr, "bpf_program__attach {}: {}", bpf_program__name(prog),
				std::strerror(errno));
			return false;
		}

		m_links.emplace_back(link);
	}

	m_cgroupFD = UniqueFD(::open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC));

	if (!m_cgroupFD)
	{
		std::println(stderr, "open /sys/fs/cgroup: {}", std::strerror(errno));
		return false;
	}

	struct bpf_program *cg_progs[] = {
		m_skel->progs.on_connect4,
		m_skel->progs.on_connect6,
	};

	for (struct bpf_program *prog : cg_progs)
	{
		struct bpf_link *link = bpf_program__attach_cgroup(prog, m_cgroupFD.handle());

		if (!link)
		{
			std::println(stderr, "bpf_program__attach_cgroup {}: {}", bpf_program__name(prog),
				std::strerror(errno));
			return false;
		}

		m_links.emplace_back(link);
	}

	struct ring_buffer *rb =
		ring_buffer__new(bpf_map__fd(m_skel->maps.events), sampleCallback, this, nullptr);

	if (!rb)
	{
		std::println(stderr, "ring_buffer__new: {}", std::strerror(errno));
		return false;
	}

	m_ringBuf.reset(rb);

	return true;
}

int EBPFManager::ringBufFd() const
{
	return ring_buffer__epoll_fd(m_ringBuf.get());
}

int EBPFManager::consume()
{
	return ring_buffer__consume(m_ringBuf.get());
}

bool EBPFManager::trackPid(std::uint32_t pid)
{
	struct tracked_pid_info info{};
	info.session_id = 1;

	const int err =
		bpf_map_update_elem(bpf_map__fd(m_skel->maps.tracked_pids), &pid, &info, BPF_NOEXIST);

	if (err < 0)
	{
		std::println(stderr, "bpf_map_update_elem tracked_pids: {}", std::strerror(-err));
		return false;
	}

	return true;
}

void EBPFManager::clearTrackedPids()
{
	const int map_fd = bpf_map__fd(m_skel->maps.tracked_pids);
	__u32 key;

	while (bpf_map_get_next_key(map_fd, nullptr, &key) == 0)
		bpf_map_delete_elem(map_fd, &key);
}

bool EBPFManager::setPackageForPid(std::uint32_t pid, std::uint32_t package_id)
{
	const int map_fd = bpf_map__fd(m_skel->maps.tracked_pids);

	struct tracked_pid_info info{};
	int err = bpf_map_lookup_elem(map_fd, &pid, &info);

	if (err < 0)
		return false;

	info.package_id = package_id;
	err = bpf_map_update_elem(map_fd, &pid, &info, BPF_EXIST);

	if (err < 0)
	{
		std::println(stderr, "bpf_map_update_elem package: {}", std::strerror(-err));
		return false;
	}

	return true;
}

bool EBPFManager::setMode(Mode mode)
{
	const int map_fd = bpf_map__fd(m_skel->maps.mode_config);
	__u32 zero = 0;
	__u32 val = mode == Mode::Enforce ? 1u : 0u;

	const int err = bpf_map_update_elem(map_fd, &zero, &val, BPF_ANY);

	if (err < 0)
	{
		std::println(stderr, "bpf_map_update_elem mode_config: {}", std::strerror(-err));
		return false;
	}

	return true;
}

bool EBPFManager::addAllowedAddr(const IPv6 &addr)
{
	const int map_fd = bpf_map__fd(m_skel->maps.allowlist);
	__u8 val = 1;

	const int err = bpf_map_update_elem(map_fd, addr.data(), &val, BPF_ANY);

	if (err < 0)
	{
		std::println(stderr, "bpf_map_update_elem allowlist: {}", std::strerror(-err));
		return false;
	}

	return true;
}

void EBPFManager::setEventCallback(EventCB cb)
{
	m_callback = std::move(cb);
}

int EBPFManager::handleEvent(std::span<const std::byte> data)
{
	if (m_callback)
		m_callback(data);

	return 0;
}

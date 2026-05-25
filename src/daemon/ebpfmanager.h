/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "blastguard.skel.h"
#include "common/net.h"
#include "common/uniquefd.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <vector>

#include <bpf/libbpf.h>

enum class Mode : std::uint8_t;

class EBPFManager
{
public:
	EBPFManager() = default;

	bool init();

	int ringBufFd() const;
	int consume();

	bool trackPid(std::uint32_t pid);
	bool setPackageForPid(std::uint32_t pid, std::uint32_t package_id);
	void clearTrackedPids();

	bool setMode(Mode mode);
	bool addAllowedAddr(const IPv6 &addr);

	using EventCB = std::move_only_function<void(std::span<const std::byte>)>;
	void setEventCallback(EventCB cb);

private:
	int handleEvent(std::span<const std::byte> data);

	template <typename T, void (*freeFunc)(T *)> struct GenericDeleter
	{
		void operator()(T *t)
		{
			if (!t)
				return;
			freeFunc(t);
		}
	};

	static void bpfLinkFree(struct bpf_link *link)
	{
		bpf_link__detach(link);
		bpf_link__destroy(link);
	}

	static void bpfSkelDestroy(struct blastguard_bpf *obj)
	{
		blastguard_bpf__destroy(obj);
	}

	using BPFLinkDeleter = GenericDeleter<struct bpf_link, bpfLinkFree>;
	using BPFLinkUptr = std::unique_ptr<struct bpf_link, BPFLinkDeleter>;

	using BPFSkelDeleter = GenericDeleter<struct blastguard_bpf, bpfSkelDestroy>;
	using BPFSkelUptr = std::unique_ptr<struct blastguard_bpf, BPFSkelDeleter>;

	using BPFRingBufDeleter = GenericDeleter<struct ring_buffer, ring_buffer__free>;
	using BPFRingBufUptr = std::unique_ptr<struct ring_buffer, BPFRingBufDeleter>;

	BPFSkelUptr m_skel;
	UniqueFD m_cgroupFD;
	BPFRingBufUptr m_ringBuf;
	std::vector<BPFLinkUptr> m_links;
	EventCB m_callback;

	friend int sampleCallback(void *ctx, void *data, std::size_t size);
};

/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "events.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 2 * 1024 * 1024);
} events SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct tracked_pid_info);
} tracked_pids SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mode_config SEC(".maps");

struct ipv6_key
{
	__u8 bytes[16];
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ipv6_key);
	__type(value, __u8);
} allowlist SEC(".maps");

SEC("raw_tp/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 parent_pid = BPF_CORE_READ(parent, tgid);
	struct tracked_pid_info *info = bpf_map_lookup_elem(&tracked_pids, &parent_pid);

	if (!info)
		return 0;

	__u32 child_pid = BPF_CORE_READ(child, tgid);
	struct tracked_pid_info new_info = *info;

	bpf_map_update_elem(&tracked_pids, &child_pid, &new_info, BPF_NOEXIST);

	struct event_fork *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;

	e->hdr.type = event_type_fork;
	e->hdr.pid = parent_pid;
	e->hdr.ppid = 0;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->child_pid = child_pid;
	e->package_id = new_info.package_id;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("raw_tp/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 tgid = BPF_CORE_READ(p, tgid);

	if (pid != tgid)
		return 0;

	bpf_map_delete_elem(&tracked_pids, &tgid);

	return 0;
}

static __always_inline int emit_open(struct trace_event_raw_sys_enter *ctx, int with_flags)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct tracked_pid_info *info = bpf_map_lookup_elem(&tracked_pids, &pid);

	if (!info)
		return 0;

	struct event_open *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;

	long n = bpf_probe_read_user_str(e->path, sizeof(e->path), (void *)ctx->args[1]);

	if (n <= 0 || e->path[0] != '/')
	{
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	e->hdr.type = event_type_open;
	e->hdr.pid = pid;
	e->hdr.ppid = 0;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->package_id = info->package_id;
	e->dfd = (__s32)ctx->args[0];
	e->flags = with_flags ? (__s32)ctx->args[2] : 0;
	e->path_len = (__u32)n;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open(ctx, 1);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int on_openat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open(ctx, 0);
}

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct tracked_pid_info *info = bpf_map_lookup_elem(&tracked_pids, &pid);

	if (!info)
		return 1;

	__u32 zero = 0;
	__u32 *mode = bpf_map_lookup_elem(&mode_config, &zero);
	__u32 enforce = mode ? *mode : 0;

	struct ipv6_key key = {};
	key.bytes[10] = 0xff;
	key.bytes[11] = 0xff;
	__builtin_memcpy(&key.bytes[12], &ctx->user_ip4, 4);

	int verdict = 1;
	__u8 blocked_flag = 0;

	if (enforce && !bpf_map_lookup_elem(&allowlist, &key))
	{
		verdict = 0;
		blocked_flag = 1;
	}

	struct event_connect *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return verdict;

	e->hdr.type = event_type_connect;
	e->hdr.pid = pid;
	e->hdr.ppid = 0;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->package_id = info->package_id;
	e->family = 4;
	e->blocked = blocked_flag;
	__builtin_memcpy(e->addr, key.bytes, 16);
	e->port = bpf_ntohs(ctx->user_port);

	bpf_ringbuf_submit(e, 0);

	return verdict;
}

SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct tracked_pid_info *info = bpf_map_lookup_elem(&tracked_pids, &pid);

	if (!info)
		return 1;

	__u32 zero = 0;
	__u32 *mode = bpf_map_lookup_elem(&mode_config, &zero);
	__u32 enforce = mode ? *mode : 0;

	struct ipv6_key key;
	__builtin_memcpy(&key.bytes[0], &ctx->user_ip6[0], 4);
	__builtin_memcpy(&key.bytes[4], &ctx->user_ip6[1], 4);
	__builtin_memcpy(&key.bytes[8], &ctx->user_ip6[2], 4);
	__builtin_memcpy(&key.bytes[12], &ctx->user_ip6[3], 4);

	int verdict = 1;
	__u8 blocked_flag = 0;

	if (enforce && !bpf_map_lookup_elem(&allowlist, &key))
	{
		verdict = 0;
		blocked_flag = 1;
	}

	struct event_connect *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return verdict;

	e->hdr.type = event_type_connect;
	e->hdr.pid = pid;
	e->hdr.ppid = 0;
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->package_id = info->package_id;
	e->family = 6;
	e->blocked = blocked_flag;
	__builtin_memcpy(e->addr, key.bytes, 16);
	e->port = bpf_ntohs(ctx->user_port);

	bpf_ringbuf_submit(e, 0);

	return verdict;
}

SEC("raw_tp/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct tracked_pid_info *info = bpf_map_lookup_elem(&tracked_pids, &pid);

	if (!info)
		return 0;

	__u32 pkg_id = info->package_id;

	struct event_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return 0;

	e->hdr.type = event_type_exec;
	e->hdr.pid = pid;
	e->hdr.ppid = BPF_CORE_READ(p, real_parent, tgid);
	e->hdr.ts_ns = bpf_ktime_get_ns();
	e->package_id = pkg_id;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
	unsigned long env_start = BPF_CORE_READ(mm, env_start);
	unsigned long env_end = BPF_CORE_READ(mm, env_end);

	__u32 arg_len = 0;

	if (arg_end > arg_start)
	{
		unsigned long total = arg_end - arg_start;
		arg_len = total > argv_max ? argv_max : (__u32)total;
	}

	if (arg_len > 0)
		bpf_probe_read_user(e->argv, arg_len, (void *)arg_start);

	e->argv_len = arg_len;

	__u32 env_len = 0;

	if (env_end > env_start)
	{
		unsigned long total = env_end - env_start;
		env_len = total > env_max ? env_max : (__u32)total;
	}

	if (env_len > 0)
		bpf_probe_read_user(e->env, env_len, (void *)env_start);

	e->env_len = env_len;

	bpf_ringbuf_submit(e, 0);

	return 0;
}

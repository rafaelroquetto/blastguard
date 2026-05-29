/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#ifdef __BPF__
#include "vmlinux.h"
#else
#include <linux/types.h>
#endif

enum
{
	argv_max = 2048,
	env_max = 16384,
	path_max = 192,
};

enum event_type : __u8
{
	event_type_exec = 1,
	event_type_fork = 2,
	event_type_open = 3,
	event_type_connect = 4,
};

enum token_bit : __u32
{
	token_bit_npm_token = (1u << 0),
	token_bit_node_auth_token = (1u << 1),
	token_bit_github_token = (1u << 2),
	token_bit_aws_access_key_id = (1u << 3),
	token_bit_aws_secret_access_key = (1u << 4),
	token_bit_aws_session_token = (1u << 5),
	token_bit_vault_token = (1u << 6),
	token_bit_ssh_auth_sock = (1u << 7),
	token_bit_docker_auth_config = (1u << 8),
};

struct event_hdr
{
	__u8 type;
	__u8 pad[3];
	__u32 pid;
	__u32 ppid;
	__u32 reserved;
	__u64 ts_ns;
};

struct event_exec
{
	struct event_hdr hdr;
	__u32 argv_len;
	__u32 env_len;
	__u32 package_id;
	__u32 reserved;
	char comm[16];
	char argv[argv_max];
	char env[env_max];
};

struct event_fork
{
	struct event_hdr hdr;
	__u32 child_pid;
	__u32 package_id;
};

struct event_open
{
	struct event_hdr hdr;
	__u32 path_len;
	__u32 package_id;
	__s32 dfd;
	__s32 flags;
	char path[path_max];
};

struct event_connect
{
	struct event_hdr hdr;
	__u32 package_id;
	__u8 addr[16];
	__u16 port;
	__u8 family;
	__u8 blocked;
};

struct tracked_pid_info
{
	__u32 session_id;
	__u32 package_id;
};

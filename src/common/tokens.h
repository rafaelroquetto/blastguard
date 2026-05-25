/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "bpf/events.h"

#include <array>
#include <cstdint>
#include <string_view>

struct TokenInfo
{
	std::string_view prefix;
	std::string_view name;
	std::uint32_t bit;
};

inline constexpr std::array<TokenInfo, 9> token_table = {{
	{"NPM_TOKEN=", "NPM_TOKEN", token_bit_npm_token},
	{"NODE_AUTH_TOKEN=", "NODE_AUTH_TOKEN", token_bit_node_auth_token},
	{"GITHUB_TOKEN=", "GITHUB_TOKEN", token_bit_github_token},
	{"AWS_ACCESS_KEY_ID=", "AWS_ACCESS_KEY_ID", token_bit_aws_access_key_id},
	{"AWS_SECRET_ACCESS_KEY=", "AWS_SECRET_ACCESS_KEY", token_bit_aws_secret_access_key},
	{"AWS_SESSION_TOKEN=", "AWS_SESSION_TOKEN", token_bit_aws_session_token},
	{"VAULT_TOKEN=", "VAULT_TOKEN", token_bit_vault_token},
	{"SSH_AUTH_SOCK=", "SSH_AUTH_SOCK", token_bit_ssh_auth_sock},
	{"DOCKER_AUTH_CONFIG=", "DOCKER_AUTH_CONFIG", token_bit_docker_auth_config},
}};

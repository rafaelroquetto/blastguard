/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

bool writeAll(int fd, std::string_view data);
bool readAll(int fd, std::string &out, std::size_t max_size);
std::string readLine(int fd, std::size_t max_size);

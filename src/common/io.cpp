/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "io.h"

#include <cerrno>

#include <unistd.h>

bool writeAll(int fd, std::string_view data)
{
	const char *p = data.data();
	std::size_t remaining = data.size();

	while (remaining > 0)
	{
		const ssize_t n = ::write(fd, p, remaining);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			return false;
		}

		if (n == 0)
			return false;

		p += n;
		remaining -= static_cast<std::size_t>(n);
	}

	return true;
}

bool readAll(int fd, std::string &out, std::size_t max_size)
{
	char chunk[4096];

	while (out.size() < max_size)
	{
		const ssize_t n = ::read(fd, chunk, sizeof(chunk));

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			return false;
		}

		if (n == 0)
			return true;

		out.append(chunk, static_cast<std::size_t>(n));
	}

	return true;
}

std::string readLine(int fd, std::size_t max_size)
{
	std::string out;
	char c;

	while (out.size() < max_size)
	{
		const ssize_t n = ::read(fd, &c, 1);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			break;
		}

		if (n == 0)
			break;

		if (c == '\n')
			break;

		out.push_back(c);
	}

	return out;
}

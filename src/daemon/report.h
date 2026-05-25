/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#pragma once

#include "common/proto.h"
#include "session.h"

#include <string>

class Report
{
public:
	static std::string render(const Session &session, Format format);
};

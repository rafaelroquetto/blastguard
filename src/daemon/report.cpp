/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rafael Roquetto
 */

#include "report.h"

#include "rules.h"

#include <format>
#include <set>
#include <string>

static const char *severityEmoji(Severity s)
{
	switch (s)
	{
	case Severity::None:
		return "";
	case Severity::Low:
		return "🟡";
	case Severity::Medium:
		return "🟠";
	case Severity::High:
		return "🔴";
	}

	return "";
}

static std::set<std::string> rotationTokens(const Session &session)
{
	std::set<std::string> out;

	for (const auto &f : session.findings())
	{
		if (f.severity != Severity::High)
			continue;

		for (const auto &t : f.tokens_exposed)
		{
			if (t != "GITHUB_TOKEN")
				out.insert(t);
		}
	}

	return out;
}

static std::string renderMarkdown(const Session &session)
{
	std::string out;
	out += std::format("# Blastguard report — phase `{}`\n\n", session.phaseName());

	auto tokens = rotationTokens(session);

	if (!tokens.empty())
	{
		out += "## 🚨 Rotate the following tokens\n\n";

		for (const auto &t : tokens)
			out += std::format("- `{}`\n", t);

		out += "\n";
	}

	const auto &findings = session.findings();

	if (findings.empty())
	{
		out += "## ✅ No findings\n\n";
		return out;
	}

	out += std::format("## Findings ({} total)\n\n", findings.size());

	for (const auto &f : findings)
	{
		const auto &info = rules::ruleInfo(f.rule_id);

		out += std::format("- **{} {}** — {} *(rule `{}` — {}, package `{}`{})*\n",
			severityEmoji(f.severity), severityToString(f.severity), f.message, info.code,
			info.title, f.package, f.blocked ? ", blocked" : "");
	}

	return out;
}

static std::string escapeJson(std::string_view s)
{
	std::string out;
	out.reserve(s.size() + 2);
	out.push_back('"');

	for (char c : s)
	{
		switch (c)
		{
		case '"':
			out += "\\\"";
			break;
		case '\\':
			out += "\\\\";
			break;
		case '\n':
			out += "\\n";
			break;
		case '\r':
			out += "\\r";
			break;
		case '\t':
			out += "\\t";
			break;
		default:
			if (static_cast<unsigned char>(c) < 0x20)
				out += std::format("\\u{:04x}",
					static_cast<unsigned int>(static_cast<unsigned char>(c)));
			else
				out.push_back(c);
		}
	}

	out.push_back('"');

	return out;
}

static std::string renderJson(const Session &session)
{
	std::string out = "{\n";
	out += std::format("  \"phase\": {},\n", escapeJson(session.phaseName()));

	auto tokens = rotationTokens(session);
	out += "  \"rotate\": [";

	bool first = true;

	for (const auto &t : tokens)
	{
		if (!first)
			out += ", ";

		first = false;
		out += escapeJson(t);
	}

	out += "],\n";

	out += "  \"findings\": [";
	first = true;

	for (const auto &f : session.findings())
	{
		if (!first)
			out += ",";

		first = false;
		out += "\n    { ";
		out += std::format("\"rule\": {}, ", escapeJson(rules::ruleInfo(f.rule_id).code));
		out += std::format("\"severity\": {}, ", escapeJson(severityToString(f.severity)));
		out += std::format("\"pid\": {}, ", f.pid);
		out += std::format("\"package\": {}, ", escapeJson(f.package));
		out += std::format("\"phase\": {}, ", escapeJson(f.lifecycle_phase));
		out += std::format("\"message\": {}, ", escapeJson(f.message));
		out += "\"tokens\": [";

		bool first_t = true;

		for (const auto &t : f.tokens_exposed)
		{
			if (!first_t)
				out += ", ";

			first_t = false;
			out += escapeJson(t);
		}

		out += "], ";
		out += std::format("\"blocked\": {}", f.blocked ? "true" : "false");
		out += " }";
	}

	out += "\n  ]\n";
	out += "}\n";

	return out;
}

std::string Report::render(const Session &session, Format format)
{
	if (format == Format::Json)
		return renderJson(session);

	return renderMarkdown(session);
}

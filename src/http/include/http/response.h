#pragma once

#include "message.h"

#include <format>

namespace leaf::network::http {

	struct response: message {

		long status;

		std::string body;

		bool is_redirection() const;
	};
}


template<>
struct std::formatter<leaf::network::http::response> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::network::http::response& response, std::format_context& ctx) const {
		return std::format_to(ctx.out(), "response (status {})\n{}", response.status, response.body);
	}
};

#pragma once

#include "http2/message.h"

#include <future>
#include <format>

namespace leaf::network::http2 {

	class stream_handler;

	class response final: public message {
	public:
		long status;

		response() = default;

		std::list<std::reference_wrapper<stream_handler>> pushed;

	};
}

template<>
struct std::formatter<leaf::network::http2::response> {
	constexpr format_parse_context::iterator
	parse(const format_parse_context& context) {
		return context.begin();
	}

	format_context::iterator
	format(const leaf::network::http2::response&, format_context&) const;
};

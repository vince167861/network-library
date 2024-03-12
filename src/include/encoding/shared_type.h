#pragma once
#include <format>

namespace encoding {

	inline struct empty_t {} empty;
}


template<>
struct std::formatter<encoding::empty_t> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const auto&, auto& ctx) const {
		return std::ranges::copy("<null>"sv, ctx.out()).out;
	}
};

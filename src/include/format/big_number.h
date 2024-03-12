#pragma once
#include "../big_number.h"
#include "format/custom.h"
#include <ranges>

template<>
struct std::formatter<big_unsigned> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const big_unsigned& str, std::format_context& ctx) const {
		auto __it = ctx.out();
		if (str.empty())
			return std::ranges::copy("0", __it).out;
		if constexpr (std::endian::native == std::endian::big)
			for (auto c: str)
				__it = std::format_to(__it, "{:02x}", c);
		else
			for (auto c: str | std::views::reverse)
				__it = std::format_to(__it, "{:02x}", c);
		return __it;
	}
};

template<>
struct formatter<big_unsigned> {

	auto format(const big_unsigned& str, format_context<char>& ctx) const {
		auto __it = ctx.out;
		if (str.empty())
			return std::ranges::copy("0", __it).out;
		if constexpr (std::endian::native == std::endian::big)
			for (auto c: str)
				__it = std::format_to(__it, "{:02x}", c);
		else
			for (auto c: str | std::views::reverse)
				__it = std::format_to(__it, "{:02x}", c);
		return __it;
	}
};

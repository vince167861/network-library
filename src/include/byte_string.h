#pragma once
#include <cstdint>
#include <format>

using byte_string = std::basic_string<std::uint8_t>;

using byte_string_view = std::basic_string_view<std::uint8_t>;


// The following explicit template specializations are to stop std::make_format_args to
// store leaf::byte_string/_view as std::basic_string/_view. The current problem is that
// GCC implementation does not check whether TD::char_type == Context::char_type.

template<>
constexpr bool std::__is_specialization_of<byte_string, std::basic_string> = false;

template<>
constexpr bool std::__is_specialization_of<byte_string_view, std::basic_string_view> = false;

template<>
struct std::formatter<byte_string> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const byte_string& str, std::format_context& ctx) const {
		auto it = ctx.out();
		if (str.empty())
			it = std::ranges::copy("(empty)", it).out;
		for (auto c: str)
			it = std::format_to(it, "{:02x}", c);
		return it;
	}
};

template<>
struct std::formatter<byte_string_view> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const byte_string_view str, std::format_context& ctx) const {
		auto it = ctx.out();
		if (str.empty())
			it = std::ranges::copy("(empty)", it).out;
		for (auto c: str)
			it = std::format_to(it, "{:02x}", c);
		return it;
	}
};

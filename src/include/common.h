#pragma once
#include <cstdint>
#include <bit>
#include <format>

namespace leaf {

	using byte_string = std::basic_string<std::uint8_t>;

	using byte_string_view = std::basic_string_view<std::uint8_t>;


	struct binary_object {

		virtual byte_string to_bytestring(std::endian = std::endian::big) const = 0;

		virtual ~binary_object() = default;
	};

	constexpr std::uint64_t to_uint64(const char* & __b, const char* __e) {
		std::uint64_t __v = 0;
		for (; __b != __e; ++__b) {
			if (*__b < '0' || *__b > '9')
				break;
			__v = __v * 10 + (*__b - '0');
		}
		return __v;
	}
}

template<>
constexpr bool std::__is_specialization_of<leaf::byte_string, std::basic_string> = false;

template<>
constexpr bool std::__is_specialization_of<leaf::byte_string_view, std::basic_string_view> = false;


template<>
struct std::formatter<leaf::byte_string> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::byte_string& str, std::format_context& ctx) const {
		auto it = ctx.out();
		if (str.empty())
			it = std::ranges::copy("(empty)", it).out;
		for (auto c: str)
			it = std::format_to(it, "{:02x}", c);
		return it;
	}
};

template<>
struct std::formatter<leaf::byte_string_view> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::byte_string_view str, std::format_context& ctx) const {
		auto it = ctx.out();
		if (str.empty())
			it = std::ranges::copy("(empty)", it).out;
		for (auto c: str)
			it = std::format_to(it, "{:02x}", c);
		return it;
	}
};

#pragma once
#include "byte_string.h"
#include <cctype>

namespace encoding::base64 {

	constexpr byte_string from(const std::string_view __v) {
		using std::literals::operator ""sv;
		auto __it = __v.begin();
		const auto __end = __v.end();
		byte_string __r;
		__r.reserve(__v.size() / 4 * 3);
		std::uint8_t chars = 0, padding = 0;
		std::uint32_t group = 0;
		for (; __it != __end; ++__it) {
			const auto __c = *__it;
			if (!std::isalnum(__c) && __c != '+' && __c != '/' && __c != '=')
				continue;
			if (__c == '=') {
				++padding;
				group <<= 6;
			} else if (padding)
				throw std::runtime_error{"ill-formed base64 message"};
			else {
				const std::uint8_t __bits = std::invoke([&] -> std::uint8_t {
					if ('A' <= __c && __c <= 'Z')
						return __c - 'A';
					if ('a' <= __c && __c <= 'z')
						return __c - 'a' + 26;
					if ('0' <= __c && __c <= '9')
						return __c - '0' + 52;
					if (__c == '+')
						return 62;
					if (__c == '/')
						return 63;
					throw std::runtime_error{"unexpected"};
				});
				group = group << 6 | __bits & 0x3f;
			}
			if (++chars == 4) {
				if (padding > 2)
					throw std::runtime_error{"ill-formed base64 message"};
				__r.push_back(group >> 16 & 0xff);
				if (padding > 1)
					break;
				__r.push_back(group >> 8 & 0xff);
				if (padding > 0)
					break;
				__r.push_back(group & 0xff);
				chars = group = 0;
			}
		}
		return __r;
	}
}

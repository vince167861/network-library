#include "http2/huffman.h"
#include <stdexcept>

constexpr char
	bit_5[] {'0', '1', '2', 'a', 'c', 'e', 'i', 'o', 's', 't'},
	bit_6[] {' ', '%', '-', '.', '/', '3', '4', '5', '6', '7', '8', '9', '=', 'A', '_', 'b', 'd', 'f', 'g', 'h', 'l', 'm', 'n', 'p', 'r', 'u'},
	bit_7[] {':', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'Y', 'j', 'k', 'q', 'v', 'w', 'x', 'y', 'z'},
	bit_8[] {'&', '*', ',', ';', 'X', 'Z'},
	bit_10[] {'!', '"', '(', ')', '?'},
	bit_11[] {'\'', '+', '|'},
	bit_12[] {'#', '>'},
	bit_13[] { 0 , '$', '@', '[', ']', '~'},
	bit_14[] {'^', '}'},
	bit_15[] {'<', '`', '{'},
	bit_19[] {'\\', static_cast<char>(195), static_cast<char>(208)},
	bit_20[] {static_cast<char>(128), static_cast<char>(130), static_cast<char>(131), static_cast<char>(162), static_cast<char>(184), static_cast<char>(194), static_cast<char>(224), static_cast<char>(226)},
	bit_21[] {static_cast<char>(153), static_cast<char>(161), static_cast<char>(167), static_cast<char>(172), static_cast<char>(176), static_cast<char>(177), static_cast<char>(179), static_cast<char>(209), static_cast<char>(216), static_cast<char>(217), static_cast<char>(227), static_cast<char>(229), static_cast<char>(230)};

namespace leaf::network::http2::internal {

	std::uint32_t get_bits_ex(const std::basic_string_view<std::uint8_t> str, std::size_t used, std::uint8_t need) {
		auto bytes_used = used / 8;
		used %= 8;
		if (used + need < 8)
			return str[bytes_used] >> 8 - used - need & ~(~0u << need);
		need -= 8 - used;
		std::uint32_t result = str[bytes_used] & ~(~0u << 8 - used);
		while (need >= 8) {
			result = result << 8 | str[++bytes_used];
			need -= 8;
		}
		return result << need | str[bytes_used + 1] >> 8 - need;
	}

	std::string from_huffman(const std::basic_string_view<std::uint8_t> str) {
		std::string result;
		const std::size_t str_bits = str.size() * 8;
		std::size_t used = 0;
		while (used < str_bits) {
			if (used + 5 > str_bits)
				break;
			if (const auto _5 = get_bits_ex(str, used, 5); _5 <= 0x9) {
				result.push_back(bit_5[_5]);
				used += 5;
				continue;
			}
			if (used + 6 > str_bits)
				break;
			if (const auto _6 = get_bits_ex(str, used, 6); 0x14 <= _6 && _6 <= 0x2d) {
				result.push_back(bit_6[_6 - 0x14]);
				used += 6;
				continue;
			}
			if (used + 7 > str_bits)
				break;
			if (const auto _7 = get_bits_ex(str, used, 7); 0x5c <= _7 && _7 <= 0x7b) {
				result.push_back(bit_7[_7 - 0x5c]);
				used += 7;
				continue;
			}
			if (used + 8 > str_bits)
				break;
			if (const auto _8 = get_bits_ex(str, used, 8); 0xf8 <= _8 && _8 <= 0xfd) {
				result.push_back(bit_8[_8 - 0xf8]);
				used += 8;
				continue;
			}
			if (used + 10 > str_bits)
				break;
			if (const auto _10 = get_bits_ex(str, used, 10); 0x3f8 <= _10 && _10 <= 0x3fc) {
				result.push_back(bit_10[_10 - 0x3f8]);
				used += 10;
				continue;
			}
			if (used + 11 > str_bits)
				break;
			if (const auto _11 = get_bits_ex(str, used, 11); 0x7fa <= _11 && _11 <= 0x7fc) {
				result.push_back(bit_11[_11 - 0x7fa]);
				used += 11;
				continue;
			}
			if (used + 12 > str_bits)
				break;
			if (const auto _12 = get_bits_ex(str, used, 12); 0xffa <= _12 && _12 <= 0xffb) {
				result.push_back(bit_12[_12 - 0xffa]);
				used += 12;
				continue;
			}
			if (used + 13 > str_bits)
				break;
			if (const auto _13 = get_bits_ex(str, used, 13); 0x1ff8 <= _13 && _13 <= 0x1ffd) {
				result.push_back(bit_13[_13 - 0x1ff8]);
				used += 13;
				continue;
			}
			if (used + 14 > str_bits)
				break;
			if (const auto _14 = get_bits_ex(str, used, 14); 0x3ffc <= _14 && _14 <= 0x3ffd) {
				result.push_back(bit_14[_14 - 0x3ffc]);
				used += 14;
				continue;
			}
			if (used + 15 > str_bits)
				break;
			if (const auto _15 = get_bits_ex(str, used, 15); 0x7ffc <= _15 && _15 <= 0x7ffe) {
				result.push_back(bit_15[_15 - 0x7ffc]);
				used += 15;
				continue;
			}
			if (used + 19 > str_bits)
				break;
			if (const auto _19 = get_bits_ex(str, used, 19); 0x7fff0 <= _19 && _19 <= 0x7fff2) {
				result.push_back(bit_19[_19 - 0x7fff0]);
				used += 19;
				continue;
			}
			if (used + 20 > str_bits)
				break;
			if (const auto _20 = get_bits_ex(str, used, 20); 0xfffe6 <= _20 && _20 <= 0xfffeb) {
				result.push_back(bit_20[_20 - 0xfffe6]);
				used += 20;
				continue;
			}
			if (used + 21 > str_bits)
				break;
			if (const auto _21 = get_bits_ex(str, used, 21); 0x1fffdc <= _21 && _21 <= 0x1fffe8) {
				result.push_back(bit_21[_21 - 0x1fffdc]);
				used += 21;
				continue;
			}
			throw std::runtime_error("unimplemented");
		}
		return result;
	}
}

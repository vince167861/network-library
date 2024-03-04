#pragma once
#include "basic_stream.h"
#include <bit>
#include <list>
#include <algorithm>

namespace internal {

	template<typename T>
	void write(const std::endian endian, byte_string& dst, const T& src, const std::size_t count = sizeof(T)) {
		const uint8_t* src_ptr = reinterpret_cast<const uint8_t*>(&src), * src_end = src_ptr + count;
		if (endian != std::endian::native) {
			std::swap(--src_ptr, --src_end);
			for (; src_ptr != src_end; --src_ptr)
				dst.push_back(*src_ptr);
		} else
			dst.append(src_ptr, src_end);
	}

	template<typename T>
	void write(const std::endian endian, ostream& dst, const T& src, const std::size_t count = sizeof(T)) {
		const uint8_t* src_ptr = reinterpret_cast<const uint8_t*>(&src), * src_end = src_ptr + count;
		byte_string data{src_ptr, src_end};
		if (endian != std::endian::native)
			std::reverse(data.begin(), data.end());
		dst.write(data);
	}

	template<typename T>
	constexpr void read(const std::endian endian, T& val, auto& src, const std::size_t count = sizeof(T)) {
		uint8_t* dst_ptr = reinterpret_cast<uint8_t *>(&val), * dst_end = dst_ptr + count;
		if (endian != std::endian::native) {
			std::swap(--dst_ptr, --dst_end);
			while (dst_ptr != dst_end)
				*dst_ptr-- = *src++;
		} else while (dst_ptr != dst_end)
			*dst_ptr++ = *src++;
	}

	template<typename T>
	constexpr T read(const std::endian endian, auto& src, const std::size_t count = sizeof(T)) {
		T val{};
		read(endian, val, src, count);
		return val;
	}

	template<class T>
	void read(const std::endian endian, T& val, istream& src, const std::size_t count = sizeof(T)) {
		std::uint8_t* dst_ptr = reinterpret_cast<uint8_t *>(&val), * dst_end = dst_ptr + count;
		if (endian != std::endian::native) {
			std::swap(--dst_ptr, --dst_end);
			while (dst_ptr != dst_end)
				*dst_ptr-- = src.read();
		} else while (dst_ptr != dst_end)
				*dst_ptr++ = src.read();
	}

	template<typename iter>
	byte_string read_bytestring(iter& src, const std::size_t count) {
		const auto begin = src;
		std::advance(src, count);
		return {begin, src};
	}


	inline bool ignore_case_equal(const std::string& a, const std::string& b) {
		return std::equal(a.begin(), a.end(), b.begin(), [](char a, char b){
			return tolower(a) == tolower(b);
		});
	}

	inline std::string to_lower(std::string_view str) {
		std::string ret(str.size(), 0);
		std::ranges::transform(str, ret.begin(), [](char c){ return tolower(c); });
		return ret;
	}

	inline std::string to_upper(const std::string& str) {
		std::string ret(str.size(), 0);
		std::ranges::transform(str, ret.begin(), [](char c){ return toupper(c); });
		return ret;
	}

	constexpr std::string_view trim_begin(const std::string_view str) {
		return {std::ranges::find_if(str, [](char c) { return std::isspace(c) == 0; }), str.end()};
	}

	constexpr std::string_view trim_end(const std::string_view str) {
		return {str.begin(), std::find_if(str.rbegin(), str.rend(), [](char c) { return std::isspace(c) == 0; }).base()};
	}

	constexpr std::string_view trim(const std::string_view str) {
		return trim_end(trim_begin(str));
	}


	inline std::list<std::string> split(const std::string_view str, const char delim) {
		std::list<std::string> list;
		auto ptr = str.begin(), begin = str.begin();
		for (; ptr != str.end(); ++ptr) {
			if (*ptr == delim) {
				list.emplace_back(begin, ptr);
				begin = ptr + 1;
			}
		}
		if (ptr != begin)
			list.emplace_back(begin, ptr);
		return list;
	}

	template<class T>
	std::pair<T, T> big_small(T a, T b) {
		if (a > b)
			return {a, b};
		return {b, a};
	}

	inline std::size_t div_ceil(const std::size_t a, const std::size_t b) {
		return a / b + (a % b ? 1 : 0);
	}

	inline std::size_t mod_not_exceed(std::size_t a, std::size_t b) {
		const auto c = a % b;
		return c ? c : b;
	}

	inline std::size_t divisible_requires(std::size_t a, std::size_t b) {
		const auto c = a % b;
		return c ? b - c : 0;
	}
}

namespace std {

	template<class T1, class T2, class U1, class U2>
	constexpr inline bool operator==(const std::pair<T1, T2>& lhs, const std::pair<U1, U2>& rhs) {
		return lhs.first == rhs.first && lhs.second == rhs.second;
	}
}

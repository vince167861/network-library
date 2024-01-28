#pragma once

#include "basic_stream.h"

#include <bit>
#include <list>
#include <string>
#include <algorithm>

namespace leaf {

	template<typename T>
	void write(std::endian endian, std::string& dest, const T& src, const std::size_t count = sizeof(T)) {
		bool big_endian = endian == std::endian::big;
		const uint8_t* src_ptr = reinterpret_cast<const uint8_t*>(&src), * src_end = src_ptr + count;
		if (big_endian) {
			std::swap(--src_ptr, --src_end);
			for (; src_ptr != src_end; --src_ptr)
				dest.push_back(*src_ptr);
		} else
			dest.append(src_ptr, src_end);
	}

	template<class Iter>
	void forward_read(Iter& source, char* begin, const char* end) {
		while (begin != end)
			*begin++ = *source++;
	}

	template<class Iter>
	void reverse_read(Iter& source, char* begin, char* end) {
		auto begin_itr = end - 1;
		const auto end_itr = begin - 1;
		while(begin_itr != end_itr)
			*begin_itr-- = *source++;
	}

	inline void reverse_write(stream& s, const void* ptr, const std::size_t bytes) {
		const auto end = static_cast<const char*>(ptr) - 1;
		for (auto begin = end + bytes; begin != end; --begin)
			s.write({begin, begin + 1});
	}


	template<class T>
	void forward_write(std::string& str, const T& data) {
		const auto begin = reinterpret_cast<const char*>(&data);
		str.append(begin, begin + sizeof(T));
	}

	template<class T>
	void reverse_write(stream& s, const T& data, const std::size_t bytes = sizeof(T)) {
		reverse_write(s, reinterpret_cast<const void*>(&data), bytes);
	}

	template<class T>
	void reverse_write(std::string& str, const T& data, const std::size_t bytes = sizeof(T)) {
		const auto begin = reinterpret_cast<const char*>(&data);
		str.append(std::make_reverse_iterator(begin + bytes), std::make_reverse_iterator(begin));
	}


	template<class Iter, class T>
	void forward_read(Iter& s, T& data) {
		auto begin = reinterpret_cast<char*>(&data);
		forward_read(s, begin, begin + sizeof(T));
	}

	template<class Iter, class T>
	void reverse_read(Iter& s, T& data) {
		auto begin = reinterpret_cast<char*>(&data);
		reverse_read(s, begin, begin + sizeof(T));
	}

	template<std::size_t S, class Iter, class T>
	void reverse_read(Iter& s, T& data) {
		auto begin = reinterpret_cast<char*>(&data);
		reverse_read(s, begin, begin + S);
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

	inline std::string_view trim_begin(const std::string_view str) {
		return {std::ranges::find_if(str, [](char c) { return std::isspace(c) == 0; }), str.end()};
	}

	inline std::string_view trim_end(const std::string_view str) {
		return {str.begin(), std::find_if(str.rbegin(), str.rend(), [](char c) { return std::isspace(c) == 0; }).base()};
	}

	inline std::string_view trim(const std::string_view str) {
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
}

namespace std {

	template<class T1, class T2, class U1, class U2>
	constexpr inline bool operator==(const std::pair<T1, T2>& lhs, const std::pair<U1, U2>& rhs) {
		return lhs.first == rhs.first && lhs.second == rhs.second;
	}
}

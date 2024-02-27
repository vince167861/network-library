#pragma once
#include <cstdint>
#include <format>
#include <map>
#include <unordered_map>
#include <list>

namespace leaf {

	using byte_string = std::basic_string<std::uint8_t>;

	using byte_string_view = std::basic_string_view<std::uint8_t>;


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

template<class K, class V>
struct std::hash<std::pair<K, V>>;

template<class... Args>
struct std::hash<std::map<Args...>>;

template<class... Args>
struct std::hash<std::unordered_map<Args...>>;

template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
	static std::hash<T> hash;
	seed ^= hash(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}

template<class K, class V>
struct std::hash<std::pair<K, V>> {

	std::size_t operator()(const std::pair<K, V>& val) {
		std::size_t result;
		hash_combine(result, val.first);
		hash_combine(result, val.second);
		return result;
	}
};

template<class... Args>
struct std::hash<std::map<Args...>> {

	std::size_t operator()(const std::map<Args...>& val) const {
		std::size_t result;
		for (auto& p: val)
			hash_combine(result, p);
		return result;
	}
};

template<class... Args>
struct std::hash<std::list<Args...>> {

	std::size_t operator()(const std::list<Args...>& val) const {
		std::size_t result;
		for (auto& p: val)
			hash_combine(result, p);
		return result;
	}
};

template<class... Args>
struct std::hash<std::unordered_map<Args...>> {

	std::size_t operator()(const std::unordered_map<Args...>& val) const {
		std::size_t result;
		for (auto& p: val)
			hash_combine(result, p);
		return result;
	}
};

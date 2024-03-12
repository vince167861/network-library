#pragma once
#include <ranges>

template <class T>
void hash_combine(std::size_t& seed, const T& v) noexcept {
	constexpr std::hash<T> hash_obj;
	seed ^= hash_obj(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

template<class K, class V>
struct std::hash<std::pair<K, V>> {

	std::size_t operator()(const std::pair<K, V>& __v) {
		std::size_t __r{};
		hash_combine(__r, __v.first);
		hash_combine(__r, __v.second);
		return __r;
	}
};

template<class T> requires std::ranges::range<T>
struct std::hash<T> {

	std::size_t operator()(const T& __v) {
		std::size_t __r{};
		for (const auto& __i: __v)
			hash_combine(__r, __i);
		return __r;
	}
};

#pragma once
#include <map>
#include <unordered_map>
#include <list>

template<class K, class V>
struct std::hash<std::pair<K, V>>;

template<class... Args>
struct std::hash<std::map<Args...>>;

template<class... Args>
struct std::hash<std::unordered_map<Args...>>;

template <class T>
void hash_combine(std::size_t& seed, const T& v) noexcept
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

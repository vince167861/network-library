#pragma once
#include <format>
#include "internal/lang_util.h"

using std::literals::operator ""sv;

template<class T> requires std::ranges::range<T> && (!internal::specialization_of<T, std::basic_string>)
struct std::formatter<T> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const T& __r, auto& ctx) const {
		auto __begin = std::ranges::cbegin(__r), __end = std::ranges::cend(__r);
		auto __it = std::ranges::copy("["sv, ctx.out()).out;
		for (; __begin != __end; ++__begin) {
			__it = std::format_to(__it, "{}", *__begin);
			if (std::next(__begin) != __end)
				__it = std::ranges::copy(", "sv, __it).out;
		}
		__it = std::ranges::copy("]"sv, __it).out;
		return __it;
	}
};

template<class C, class... Ts>
struct std::formatter<std::variant<Ts...>, C> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const std::variant<Ts...>& __v, auto& ctx) const {
		auto __it = ctx.out();
		if (sizeof...(Ts))
			try_format_<0>(__v, __it);
		return __it;
	}

private:
	template<std::size_t __i>
	void try_format_(const std::variant<Ts...>& __v, auto& it) const {
		if (__v.index() != __i) {
			if constexpr (__i  + 1 < sizeof...(Ts))
				try_format_<__i + 1>(__v, it);
		} else
			it = std::format_to(it, "{}", std::get<__i>(__v));
	}
};

template<class C, class... Ts>
struct std::formatter<std::tuple<Ts...>, C> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const std::tuple<Ts...>& __v, auto& ctx) const {
		auto __it = std::ranges::copy("["sv, ctx.out()).out;
		if constexpr (sizeof...(Ts))
			format_i_<0>(__v, __it);
		return std::ranges::copy("]"sv, __it).out;
	}

private:
	template<std::size_t __i>
	void format_i_(const std::tuple<Ts...>& __v, auto& __it) const {
		__it = std::format_to(__it, "<{}>: {}", __i, std::get<__i>(__v));
		if constexpr (__i + 1 < sizeof...(Ts)) {
			__it = std::ranges::copy(", "sv, __it).out;
			format_i_<__i + 1>(__v, __it);
		}
	}
};

template<class C, class T>
struct std::formatter<std::optional<T>, C> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const std::optional<T>& __v, auto& ctx) const {
		if (!__v)
			return std::ranges::copy("(no value)"sv, ctx.out()).out;
		return std::format_to(ctx.out(), "{}", __v.value());
	}
};

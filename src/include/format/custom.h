#pragma once
#include "internal/lang_util.h"
#include <format>

// Custom formatter; using global namespace

template<class T, class CharT = char>
struct format_traits;

template<class T, class CharT = char>
struct formatter {

	formatter() = delete; // missing specialization for type T
};

template<class T>
concept has_element_names = requires
{
	{ format_traits<T>::element_names } -> internal::is_array;
};

template<class T>
concept has_ignored = requires { { format_traits<T>::ignored } -> std::convertible_to<bool>; };

template<class CharT, class Iter = std::back_insert_iterator<std::string>>
struct format_context {

	using char_type = CharT;

	using iterator = Iter;

	using fmt_string_store_iterator = typename std::basic_string_view<CharT>::const_iterator;

	Iter out;
};

template<class T, class CharT = char>
concept formattable = requires (formatter<T, CharT> __f, T t, format_context<CharT> ctx, std::size_t i) {
	__f.format(t, ctx, i);
};

template<class Context, class... Ts>
struct format_args: formatter<std::remove_cvref_t<Ts>, typename Context::char_type>... {
	using formatter<std::remove_cvref_t<Ts>, typename Context::char_type>::format...;
};

template<class CharT, class... Ts>
struct format_string {

	using store_iterator = typename std::basic_string_view<CharT>::const_iterator;

	std::basic_string_view<CharT> string_store_;

	std::array<std::basic_string_view<CharT>, sizeof...(Ts)> range_store_;

	consteval format_string(const std::basic_string_view<CharT>& str)
		: string_store_{str} {
		auto __it = string_store_.begin();
		const auto __end = string_store_.end();
		std::size_t i = 0;
		for (; __it != __end; ++__it) {
			if (*__it != '{')
				continue;
			if (i + 1 > sizeof...(Ts))
				throw std::format_error("too many arguments in format string");
			auto __rit = __it + 1;
			while (__rit != __end && *__rit != '}')
				++__rit;
			if (*__rit != '}')
				throw std::format_error("left and right braces do not match");
			range_store_[i] = {__it, __rit};
			__it = __rit;
		}
	}
};

template<class CharT = char, class Iter, class... Ts>
Iter format_to(const Iter __it, const std::size_t indent, const format_string<CharT, Ts...>& fmt_str, Ts&&... __args) {
	using Context = format_context<CharT, Iter>;
	constexpr format_args<Context, Ts...> fmt_args;
	Context ctx{__it};
	typename format_string<CharT, Ts...>::store_iterator fmt_begin = fmt_str.string_store_.begin();
	[&] <std::size_t... __i> (std::index_sequence<__i...>) {
		(([&] {
			ctx.out = std::copy(fmt_begin, fmt_str.range_store_[__i].begin(), ctx.out);
			ctx.out = fmt_args.format(std::forward<Ts&&>(__args), ctx, indent);
			fmt_begin = fmt_str.range_store_[__i].end() + 1;
		}(), __i), ...);
	}(std::make_index_sequence<sizeof...(Ts)>{});
	return std::copy(fmt_begin, fmt_str.string_store_.end(), ctx.out);
}

template<class CharT = char, class... Ts>
std::string format(const format_string<CharT, Ts...>& fmt_str, const std::size_t indent = 0, Ts&&... __args) {
	std::basic_string<CharT> __r;
	std::back_insert_iterator __it{__r};
	::format_to(__it, indent, fmt_str, std::forward<Ts&&>(__args)...);
	return __r;
}

template<class T> requires std::ranges::range<T> && (!internal::specialization_of<T, std::basic_string>)
struct formatter<T> {

	auto format(const T& __r, auto& ctx, const std::size_t indent) const {
		using std::literals::operator ""sv;
		auto __begin = std::ranges::cbegin(__r), __end = std::ranges::cend(__r);
		auto __it = std::ranges::copy("["sv, ctx.out).out;
		for (; __begin != __end; ++__begin) {
			if constexpr (formattable<std::remove_cvref_t<decltype(*__begin)>>)
				__it = ::format_to(__it, indent, {"{}"}, *__begin);
			else
				__it = std::format_to(__it, "{}", *__begin);
			if (std::next(__begin) != __end)
				__it = std::ranges::copy(", "sv, __it).out;
		}
		return std::ranges::copy("]"sv, __it).out;
	}
};

template<class T, class Traits>
struct formatter<std::optional<T>, Traits> {

	auto format(const std::optional<T>& __v, auto& ctx, const std::size_t indent) const {
		using std::literals::operator ""sv;
		auto __it = ctx.out;
		if (!__v)
			return std::ranges::copy("(no value)"sv, __it).out;
		if constexpr (formattable<T>)
			return ::format_to(__it, indent, {"{}"}, __v.value());
		return std::format_to(__it, "{}", __v.value());
	}
};

template<class... Ts, class Traits>
struct formatter<std::variant<Ts...>, Traits> {

	auto format(const std::variant<Ts...>& __v, auto& ctx, const std::size_t indent) const {
		auto __it = ctx.out;
		if constexpr (sizeof...(Ts))
			try_format_<0>(__v, __it, indent);
		return __it;
	}

private:
	template<std::size_t __i>
	void try_format_(const std::variant<Ts...>& __v, auto& __it, const std::size_t indent) const {
		if (__v.index() != __i) {
			if constexpr (__i  + 1 < sizeof...(Ts))
				try_format_<__i + 1>(__v, __it, indent);
		} else if constexpr (formattable<std::tuple_element_t<__i, std::tuple<Ts...>>>)
			__it = ::format_to(__it, indent, {"{}"}, std::get<__i>(__v));
		else
			__it = std::format_to(__it, "{}", std::get<__i>(__v));
	}
};

template<class... Ts>
struct formatter<std::tuple<Ts...>> {

	using Traits = format_traits<std::tuple<Ts...>>;

	auto format(const std::tuple<Ts...>& __v, auto& ctx, const std::size_t indent) const {
		using std::literals::operator ""sv;
		auto __it = std::ranges::copy("{\n"sv, ctx.out).out;
		[&] <std::size_t... __i> (std::index_sequence<__i...>) {
			(([&] {
				using T = std::tuple_element_t<__i, std::tuple<Ts...>>;
				if constexpr (has_ignored<T>) {
					if constexpr (format_traits<T>::ignored)
						return;
				}
				__it = std::ranges::fill_n(__it, (indent + 1) * 4, ' ');
				if constexpr (has_element_names<std::tuple<Ts...>>) {
					if constexpr (__i < std::extent_v<decltype(Traits::element_names)>)
						__it = std::format_to(__it, "[[{}]] ", Traits::element_names[__i]);
					else
						__it = std::format_to(__it, "[[{}]] ", __i);
				} else
					__it = std::format_to(__it, "[[{}]] ", __i);
				if constexpr (formattable<T>)
					__it = ::format_to(__it, indent + 1, {"{},\n"}, std::get<__i>(__v));
				else
					__it = std::format_to(__it, "{},\n", std::get<__i>(__v));
			}(), __i), ...);
		}(std::make_index_sequence<sizeof...(Ts)>{});
		__it = std::ranges::fill_n(__it, indent * 4, ' ');
		return std::ranges::copy("}"sv, __it).out;
	}
};

template<int>
struct unique_tag {};

template<int __id>
struct format_traits<unique_tag<__id>> {

	static constexpr bool ignored = true;
};

template<int Name>
struct std::formatter<unique_tag<Name>> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const auto&, auto& ctx) const {
		return std::format_to(ctx.out(), "{}{}{}{}",
			static_cast<char>(Name >> 24), static_cast<char>(Name >> 16), static_cast<char>(Name >> 8),
			static_cast<char>(Name));
	}
};

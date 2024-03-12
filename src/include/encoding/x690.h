#pragma once
#include "basic_stream.h"
#include "format/custom.h"
#include "format/byte_string.h"
#include "format/big_number.h"
#include "internal/lang_util.h"
#include "encoding/shared_type.h"
#include <variant>
#include <list>
#include <set>
#include <any>

namespace encoding::x690 {

	enum class tag_class_t: std::uint8_t {
		universal = 0b00, application = 0b01, context_specific = 0b10, private_tag = 0b11
	};

	enum class tag_t: std::size_t {
		end_of_content = 0, boolean = 1, integer = 2, bitstring = 3, octetstring = 4, null = 5, object_id = 6,
		object_descriptor = 7, external = 8, real = 9, enumerated = 10, embedded_pdv = 11, utf8_string = 12,
		sequence = 16, set = 17, generalized_time = 23, utc_time = 24, visible_string = 26
	};


	struct content_head {

		tag_class_t tag_class;

		bool constructed;

		std::size_t tag;

		std::optional<std::size_t> size;
	};

	std::pair<content_head, std::size_t> parse_head(istream&);


	struct parse_context {

		istream& source;

		std::size_t consumed{0};

		parse_context(istream& __s): source(__s) {}

		auto& peek_head() {
			ensure_head_();
			return head_.value();
		}

		bool end_of_content(parse_context& sub_ctx) const {
			if (!content_size_) {
				const auto& sub_head = sub_ctx.peek_head();
				return sub_head.tag_class == tag_class_t::universal &&
					static_cast<tag_t>(sub_head.tag) == tag_t::end_of_content;
			}
			return head_size_ + sub_ctx.consumed >= content_size_.value();
		}

		template<class T>
		std::optional<content_head> get_head();

		content_head get_any_head() {
			ensure_head_();
			std::optional<content_head> __r;
			std::swap(__r, head_);
			return __r.value();
		}

		template<class T>
		bool check_head();

	private:
		std::optional<content_head> head_;

		std::size_t head_size_{0};

		std::optional<std::size_t> content_size_;

		void ensure_head_() {
			if (!head_) {
				auto head_r = parse_head(source);
				head_ = head_r.first;
				content_size_ = head_->size;
				consumed += head_size_ = head_r.second;
			}
		}
	};


	namespace internal {

		template<class Pair, class T>
		concept first_type_is = std::is_same_v<typename Pair::first_type, T>;

		template<class Pair, class T>
		concept second_type_is = std::is_same_v<typename Pair::second_type, T>;

		template<class T>
		concept basic_deserializable = requires (parse_context& ctx) { T::deserialize(ctx); };

		template<class T>
		concept default_deserializable = requires {
			{ T::__with_default } -> std::convertible_to<bool>;
			requires T::__with_default;
			requires basic_deserializable<T>;
		};

		template<class T>
		concept complete_deserializable = requires (parse_context& ctx) {
			{ T::tag_class } -> std::common_with<tag_class_t>;
			{ T::tag_value } -> std::common_with<std::size_t>;
			requires basic_deserializable<T>;
		};
	}

	template<class T>
	struct optional;

	template<class T, auto default_value>
	struct with_default;

	template<class... Ts>
	struct choice;

	struct undefined;

	template<class T>
	concept deserializable = internal::complete_deserializable<T> || ::internal::specialization_of<T, optional> ||
		internal::default_deserializable<T> || ::internal::specialization_of<T, choice> || std::same_as<T, undefined>;

	template<class T> requires internal::basic_deserializable<T>
	using deserialized_type = std::invoke_result_t<decltype(T::deserialize), parse_context&>;

	template<class T>
	bool type_match(const content_head&) = delete;

	template<class T> requires internal::complete_deserializable<T>
	bool type_match(const content_head& result) {
		return result.tag_class == T::tag_class && result.tag == T::tag_value;
	}

	template<class T> requires internal::default_deserializable<T> || ::internal::specialization_of<T, optional> ||
		::internal::specialization_of<T, choice> || std::same_as<T, undefined>
	bool type_match(const content_head&) {
		return true;
	}


	template<class T>
	std::optional<content_head> parse_context::get_head() {
		static_assert(deserializable<T>);
		ensure_head_();
		std::optional<content_head> __r;
		if (type_match<T>(head_.value()))
			std::swap(__r, head_);
		return __r;
	}

	template<class T>
	bool parse_context::check_head() {
		static_assert(deserializable<T>);
		ensure_head_();
		return type_match<T>(head_.value());
	}


	template<class T> requires deserializable<T>
	deserialized_type<T> parse(parse_context& ctx) {
		if (!ctx.check_head<T>())
			throw std::runtime_error{"tag does not match"};
		return T::deserialize(ctx);
	}

	template<class T> requires deserializable<T>
	deserialized_type<T> parse(istream& __s) {
		parse_context ctx{__s};
		return parse<T>(ctx);
	}


	template<class T, tag_class_t __tag_class, std::size_t __tag_value> requires internal::basic_deserializable<T>
	struct implicit_tagged: private T {

		static constexpr auto tag_class{__tag_class};

		static constexpr auto tag_value{__tag_value};

		using T::deserialize;
	};

	template<class T, tag_class_t __tag_class, std::size_t __tag_value> requires deserializable<T>
	struct explicit_tagged {

		static constexpr auto tag_class{__tag_class};

		static constexpr auto tag_value{__tag_value};

		static deserialized_type<T> deserialize(parse_context& this_ctx) {
			this_ctx.get_any_head();
			parse_context ctx{this_ctx.source};
			auto __r{parse<T>(ctx)};
			this_ctx.consumed += ctx.consumed;
			return __r;
		}
	};

	template<class T>
	struct optional {

		static_assert(deserializable<T>);

		static std::optional<deserialized_type<T>> deserialize(parse_context& ctx) {
			if (!ctx.check_head<T>())
				return std::nullopt;
			return T::deserialize(ctx);
		}
	};

	template<class T, auto default_value>
	struct with_default {

		static constexpr bool __with_default = true;

		static_assert(deserializable<T> && std::is_invocable_r_v<deserialized_type<T>, decltype(default_value)>);

		static auto deserialize(parse_context& ctx) {
			if (!ctx.check_head<T>())
				return default_value();
			return T::deserialize(ctx);
		}
	};

	template<class... Ts>
	struct choice {

		static_assert((deserializable<Ts> && ...) && sizeof...(Ts));

		using deserialized_type = std::variant<deserialized_type<Ts>...>;

		static deserialized_type deserialize(parse_context& ctx) {
			return try_deserialize_<0>(ctx);
		}

	private:
		template<std::size_t __i>
		static deserialized_type try_deserialize_(parse_context& ctx) {
			using T = std::tuple_element_t<__i, std::tuple<Ts...>>;
			if (!ctx.check_head<T>()) {
				if constexpr (__i + 1 < sizeof...(Ts))
					return try_deserialize_<__i + 1>(ctx);
				throw std::runtime_error{"data is not one of choice"};
			}
			return deserialized_type{std::in_place_index<__i>, T::deserialize(ctx)};
		}
	};

	struct undefined {

		content_head head;

		std::variant<byte_string, std::list<undefined>> item;

		static undefined deserialize(parse_context&);
	};


	struct boolean {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::boolean)};

		static bool deserialize(parse_context&);
	};

	struct integer {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::integer)};

		static big_unsigned deserialize(parse_context&);
	};

	template<class T> requires std::is_enum_v<T>
	struct enumerated {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::integer)};

		static T deserialize(parse_context& ctx) {
			const auto __v = integer::deserialize(ctx);
			if (__v.bit_used() > sizeof(std::underlying_type_t<T>) * 8)
				throw std::runtime_error{"enumerated value overflow"};
			return reinterpret_cast<const T&>(*__v.data());
		}
	};

	struct bit_string {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::bitstring)};

		std::uint8_t unused_bits;

		byte_string data;

		static bit_string deserialize(parse_context&);
	};

	struct octet_string {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::octetstring)};

		static byte_string deserialize(parse_context&);
	};

	struct visible_string {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::visible_string)};

		static std::string deserialize(parse_context&);
	};

	struct null {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::null)};

		static empty_t deserialize(parse_context&);
	};

	struct object_identifier {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::object_id)};

		std::list<unsigned> components;

		static object_identifier deserialize(parse_context&);
	};

	struct external {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::external)};
	};

	struct real {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::real)};

		static double deserialize(parse_context&);
	};

	template<int Name, class... Ts> requires (deserializable<Ts> && ...)
	struct sequence {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::sequence)};

		using deserialized_type = std::tuple<deserialized_type<Ts>..., unique_tag<Name>>;

		static deserialized_type deserialize(parse_context& this_ctx) {
			this_ctx.get_any_head();
			parse_context ctx{this_ctx.source};
			deserialized_type __r{parse<Ts>(ctx)..., {}};
			this_ctx.consumed += ctx.consumed;
			return __r;
		}
	};

	template<deserializable T>
	struct sequence_of {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::sequence)};

		static auto
		deserialize(parse_context& this_ctx) {
			const auto head = this_ctx.get_any_head();
			if (!head.constructed)
				throw std::runtime_error{"sequence of must be constructed"};
			std::list<deserialized_type<T>> __r;
			parse_context ctx{this_ctx.source};
			while (!this_ctx.end_of_content(ctx)) {
				__r.push_back(T::deserialize(ctx));
				this_ctx.consumed += ctx.consumed;
			}
			return __r;
		}
	};


	template<class T> requires deserializable<T>
	struct set_of {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::set)};

		static auto
		deserialize(parse_context& this_ctx) {
			const auto head = this_ctx.get_any_head();
			if (!head.constructed)
				throw std::runtime_error{"sequence of must be constructed"};
			std::list<deserialized_type<T>> __r;
			parse_context ctx{this_ctx.source};
			while (!this_ctx.end_of_content(ctx))
				__r.push_back(T::deserialize(ctx));
			this_ctx.consumed += ctx.consumed;
			return __r;
		}
	};

	using generalized_time = implicit_tagged<
		visible_string, tag_class_t::universal, static_cast<std::size_t>(tag_t::generalized_time)>;

	using utc_time = implicit_tagged<
		visible_string, tag_class_t::universal, static_cast<std::size_t>(tag_t::utc_time)>;

	struct sequence_any {

		static constexpr auto tag_class{tag_class_t::universal};

		static constexpr auto tag_value{static_cast<std::size_t>(tag_t::sequence)};

		std::any values;

		static sequence_any deserialize(parse_context&);

		auto& get() const;
	};

	using any = choice<boolean, integer, real, bit_string, octet_string, null, sequence_any, object_identifier,
		generalized_time, utc_time, undefined>;

	inline auto& sequence_any::get() const {
		return std::any_cast<const std::list<any::deserialized_type>&>(values);
	}
}


template<>
struct std::formatter<encoding::x690::undefined> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const encoding::x690::undefined& __v, auto& ctx) const {
		return std::format_to(ctx.out(), "<unknown of size {}; not parsed>", __v.head.size.value_or(0));
	}
};

template<>
struct std::formatter<encoding::x690::bit_string> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const encoding::x690::bit_string& __v, auto& ctx) const {
		big_unsigned __t{__v.data};
		__t >>= __v.unused_bits;
		return std::format_to(ctx.out(), "{}", __t);
	}
};

template<>
struct std::formatter<encoding::x690::object_identifier> {

	constexpr auto parse(auto& ctx) {
		return ctx.begin();
	}

	auto format(const encoding::x690::object_identifier& __v, auto& ctx) const {
		auto __it = std::ranges::copy("{"sv, ctx.out()).out;
		for (auto __c: __v.components)
			__it = std::format_to(__it, " {}", __c);
		return std::ranges::copy(" }"sv, __it).out;
	}
};

template<>
struct formatter<encoding::x690::object_identifier> {

	auto format(const encoding::x690::object_identifier& __v, auto& ctx, const std::size_t) const {
		using std::literals::operator ""sv;
		auto __it = std::ranges::copy("{"sv, ctx.out).out;
		for (auto __c: __v.components)
			__it = std::format_to(__it, " {}", __c);
		return std::ranges::copy(" }"sv, __it).out;
	}
};

template<class Traits>
struct formatter<encoding::x690::sequence_any, Traits> {

	auto format(const encoding::x690::sequence_any& __v, auto& ctx, const std::size_t indent) const {
		auto __it = ctx.out;
		return ::format_to(__it, indent, {"{}"}, __v.get());
	}
};

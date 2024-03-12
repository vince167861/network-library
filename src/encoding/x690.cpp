#include "encoding/x690.h"
#include "internal/utils.h"
#include <stdexcept>
#include <optional>
#include <cmath>
#include <functional>

using namespace internal;

void concat(encoding::x690::bit_string& __a, const encoding::x690::bit_string& __b) {
	__a.data.reserve(__a.data.size() + __b.data.size());
	if (__a.unused_bits == 0) {
		__a.data += __b.data;
		__a.unused_bits = __b.unused_bits;
		return;
	}
	const auto b_size = __b.data.size();
	for (std::size_t i = 0; i < b_size; ++i) {
		__a.data.back() |= __b.data[i] >> __a.unused_bits;
		if (i == b_size - 1 && __a.unused_bits + __b.unused_bits < 8)
			__a.data.push_back(__b.data[i] << 8 - __a.unused_bits & 0xff);
	}
}

struct identifier_leading {
	std::uint8_t tag: 5;
	bool constructed: 1;
	encoding::x690::tag_class_t tag_class: 2;
};

struct var_length_value {
	std::uint8_t value: 7;
	bool has_next: 1;
};

struct length_leading {
	std::uint8_t length: 7;
	bool long_or_eoc: 1;
};

namespace encoding::x690 {

	std::pair<content_head, std::size_t>
	parse_head(istream& __s) {
		const auto idn = read<identifier_leading>(std::endian::big, __s);
		std::size_t read_size = 1;
		const std::size_t tag = std::invoke([&] -> std::size_t {
			if (idn.tag != 0b11111)
				return idn.tag;
			std::size_t __t = 0;
			for (bool __next = true; __next; ) {
				const auto [value, has_next] =
					read<var_length_value>(std::endian::big, __s);
				__t = __t << 7 | value;
				__next = has_next;
				++read_size;
			}
			return __t;
		});
		const std::optional<std::size_t> length = std::invoke([&] -> std::optional<std::size_t> {
			const auto [length, long_or_eoc] = read<length_leading>(std::endian::big, __s);
			++read_size;
			if (!long_or_eoc)
				return length;
			if (length == 0) {
				if (!idn.constructed)
					throw std::logic_error{"primitives must use length of definite form"};
				return std::nullopt;
			}
			if (length > sizeof(std::size_t))
				throw std::runtime_error{"length overflow"};
			if (length == 0b1111111)
				throw std::runtime_error{"unexpected length"};
			std::size_t __v = 0;
			for (std::size_t i = 0; i < length; ++i)
				__v = __v << 8 | __s.read();
			read_size += length;
			return __v;
		});
		if (!idn.constructed && !length)
			throw std::logic_error{"primitive value must use length of definite form"};
		return {{idn.tag_class, idn.constructed, tag, length}, read_size};
	}

	undefined undefined::deserialize(parse_context& this_ctx) {
		const auto head = this_ctx.get_any_head();
		if (head.size) {
			this_ctx.consumed += head.size.value();
			return {head, {this_ctx.source.read(head.size.value())}};
		}
		std::list<undefined> items;
		parse_context ctx{this_ctx.source};
		while (!this_ctx.end_of_content(ctx)) {
			items.push_back(parse<undefined>(ctx));
			this_ctx.consumed += ctx.consumed;
		}
		this_ctx.consumed += ctx.consumed;
		return {head, {std::move(items)}};
	}

	bool
	boolean::deserialize(parse_context& ctx) {
		const auto head = ctx.get_any_head();
		if (head.constructed || !head.size)
			throw std::runtime_error{"boolean must use length of definite form"};
		const auto __s = head.size.value();
		if (__s != 1)
			throw std::runtime_error{"boolean must contain only single octet"};
		const bool __v = ctx.source.read() != 0;
		ctx.consumed += 1;
		return __v;
	}

	big_unsigned
	integer::deserialize(parse_context& ctx) {
		const auto head = ctx.get_any_head();
		if (head.constructed || !head.size)
			throw std::runtime_error{"integer must use length of definite form"};
		const auto __s = head.size.value();
		big_unsigned __v{ctx.source.read(__s), std::nullopt, std::endian::big};
		ctx.consumed += __s;
		return __v;
	}

	bit_string
	bit_string::deserialize(parse_context& this_ctx) {
		const auto head = this_ctx.get_any_head();
		if (head.constructed) {
			bit_string __v;
			parse_context ctx{this_ctx.source};
			while (!this_ctx.end_of_content(ctx)) {
				concat(__v, deserialize(ctx));
				this_ctx.consumed += ctx.consumed;
			}
			return __v;
		}
		if (!head.size)
			throw std::runtime_error{"primitive bitstring must use length of definite form"};
		bit_string __v{this_ctx.source.read(), this_ctx.source.read(head.size.value() - 1)};
		this_ctx.consumed += head.size.value();
		if (__v.unused_bits > 7)
			throw std::logic_error{"bitstring must not contain more than 7 unused bits"};
		if (__v.data.empty() && __v.unused_bits != 0)
			throw std::logic_error{"empty bitstring must have no unused bit"};
		return __v;
	}

	byte_string
	octet_string::deserialize(parse_context& this_ctx) {
		const auto head = this_ctx.get_any_head();
		if (head.constructed) {
			byte_string __v;
			parse_context ctx{this_ctx.source};
			while (!this_ctx.end_of_content(ctx)) {
				__v.append(deserialize(ctx));
				this_ctx.consumed += ctx.consumed;
			}
			return __v;
		}
		if (!head.size)
			throw std::runtime_error{"primitive octetstring must use length of definite form"};
		const auto __s = head.size.value();
		const byte_string __v{this_ctx.source.read(__s)};
		this_ctx.consumed += __s;
		return __v;
	}

	std::string visible_string::deserialize(parse_context& ctx) {
		const auto __r = octet_string::deserialize(ctx);
		return reinterpret_cast<const std::string&>(__r);
	}

	empty_t
	null::deserialize(parse_context& ctx) {
		const auto head = ctx.get_any_head();
		if (head.constructed || !head.size || head.size.value() != 0)
			throw std::runtime_error{"null must be a primitive with no content"};
		return {};
	}

	object_identifier
	object_identifier::deserialize(parse_context& ctx) {
		const auto head = ctx.get_any_head();
		if (head.constructed || !head.size)
			throw std::runtime_error{"object identifier must use length of definite form"};
		std::list<unsigned> __r;
		const auto __s = head.size.value();
		const auto sub_ids = ctx.source.read(__s);
		ctx.consumed += __s;
		auto it = sub_ids.begin();
		const auto __begin = sub_ids.begin(), __end = sub_ids.end();
		unsigned sub_id = 0;
		for (; it != __end; ++it) {
			const auto __v = reinterpret_cast<const var_length_value&>(*it);
			if (it == __begin) {
				if (__v.has_next)
					throw std::logic_error{"first subidentifier must have exactly one octet"};
				__r.push_back(__v.value / 40);
				__r.push_back(__v.value % 40);
				continue;
			}
			sub_id = sub_id << 7 | __v.value;
			if (!__v.has_next) {
				__r.push_back(sub_id);
				sub_id = 0;
			}
		}
		if (sub_id != 0)
			throw std::runtime_error{"incomplete object identifier"};
		return {__r};
	}


	enum class real_exp_size: std::uint8_t {
		one = 0b00, two = 0b01, three = 0b10, size = 0b11
	};

	enum class real_base_t: std::uint8_t {
		base_2 = 0b00, base_8 = 0b01, base_16 = 0b10, base_reserved = 0b11
	};

	enum class real_number_representation: std::uint8_t {
		iso6093_nr1 = 1, iso6093_nr2 = 2, iso6093_nr3 = 3
	};

	union real_leading {
		struct {
			real_exp_size exp_size : 2;
			std::uint8_t mantissa_scaling : 2;
			real_base_t base : 2;
			bool mantissa_negative : 1;
			bool binary : 1;
		};
		struct {
			std::uint8_t special_value : 6;
			bool special : 1;
			bool : 1;
		};
		struct {
			real_number_representation repr : 6;
			bool : 2;
		};
	};

	double
	real::deserialize(parse_context& ctx) {
		const auto head = ctx.get_any_head();
		if (head.constructed || !head.size)
			throw std::runtime_error{"real must be primitive of definite length"};
		const auto __s = head.size.value();
		if (__s == 0)
			return 0.;
		const auto first = read<real_leading>(std::endian::big, ctx.source);
		ctx.consumed += sizeof(real_leading);
		if (first.binary) {
			const auto exp_size = [&] -> std::size_t {
				switch (first.exp_size) {
					case real_exp_size::one:
						return 1;
					case real_exp_size::two:
						return 2;
					case real_exp_size::three:
						return 3;
					case real_exp_size::size: {
						const auto __v = read<std::uint8_t>(std::endian::big, ctx.source);
						++ctx.consumed;
						return __v;
					}
					default:
						throw std::runtime_error{"unexpected exp_size"};
				}
			}();
			const auto exp = [&] -> double {
				double __v = 0;
				for (std::size_t i = 0; i < exp_size; ++i)
					__v = __v * 256 + ctx.source.read();
				ctx.consumed += exp_size;
				return __v;
			}();
			const double mantissa_a = (first.mantissa_negative ? -1. : 1.) * std::pow(2., first.mantissa_scaling);
			double mantissa_b = 0;
			for (std::size_t i = 0; i < __s - exp_size; ++i)
				mantissa_b = mantissa_b * 256 + ctx.source.read();
			switch (first.base) {
				case real_base_t::base_2:
					return mantissa_a * mantissa_b * std::pow(2., exp);
				case real_base_t::base_8:
					return mantissa_a * mantissa_b * std::pow(8., exp);
				case real_base_t::base_16:
					return mantissa_a * mantissa_b * std::pow(16., exp);
				default:
					throw std::runtime_error{"unexpected"};
			}
		}
		if (first.special) {
			switch (first.special_value) {
				case 0b000000:
					return std::numeric_limits<double>::infinity();
				case 0b000001:
					return - std::numeric_limits<double>::infinity();
				default:
					throw std::runtime_error{"unexpected"};
			}
		}
		const auto decimal_string = ctx.source.read(__s);
		ctx.consumed += __s;
		const auto __begin = reinterpret_cast<const char*>(decimal_string.data()), __end = __begin + decimal_string.size();
		double __v;
		if (std::from_chars(__begin, __end, __v).ec != std::errc{})
			throw std::runtime_error{"ill-formed real number"};
		return __v;
	}

	sequence_any sequence_any::deserialize(parse_context& this_ctx) {
		const auto head = this_ctx.get_any_head();
		if (!head.constructed)
			throw std::runtime_error{"sequence must be constructed"};
		std::list<any::deserialized_type> __r;
		parse_context ctx{this_ctx.source};
		while (!this_ctx.end_of_content(ctx))
			__r.push_back(any::deserialize(ctx));
		this_ctx.consumed += ctx.consumed;
		return {__r};
	}
}

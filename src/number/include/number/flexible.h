#pragma once

#include "number_base.h"
#include <vector>
#include <ranges>

namespace leaf {

	class var_unsigned : public number_base {

	public:
		using unit_t = uint32_t;

		std::size_t bits() const override;

		std::size_t data_units() const override;

		static_assert(std::is_unsigned_v<unit_t>);

		std::vector<unit_t> data;

	protected:
		bool unsigned_add_(std::size_t pos, unit_t val, bool carry = false);

		std::size_t bits_;

	public:
		var_unsigned(std::size_t bits = 0, unit_t val = 0);

		var_unsigned(const number_base&);

		static var_unsigned from_bytes(std::string_view bytes);

		static var_unsigned from_little_endian_bytes(std::string_view bytes);

		static var_unsigned from_hex(std::string_view hex);

		static var_unsigned from_little_endian_hex(std::string_view hex);

		template<class T> requires std::is_integral_v<T>
		static var_unsigned from_number(T val) {
			var_unsigned ret(sizeof(T) * 8);
			for (std::size_t i = 0; i < ret.data_units(); ++i)
				ret[i] = i * unit_bytes < sizeof(T) ? val >> (unit_bits * i) : 0;
			return ret;
		}

		var_unsigned operator+(const var_unsigned&) const;

		var_unsigned& operator+=(const var_unsigned&);

		var_unsigned operator-(const var_unsigned&) const;

		var_unsigned& operator-=(const var_unsigned&);

		var_unsigned operator*(const var_unsigned&) const;

		var_unsigned operator<<(std::size_t) const;

		var_unsigned& operator<<=(std::size_t);

		var_unsigned operator>>(std::size_t) const;

		var_unsigned& operator>>=(std::size_t);

		var_unsigned operator^(const var_unsigned&) const;

		var_unsigned& operator^=(const var_unsigned&);

		var_unsigned operator~() const;

		var_unsigned operator%(const var_unsigned& modulus) const;

		friend var_unsigned exp_mod(const var_unsigned& base, var_unsigned exp, const var_unsigned& modulus);

		std::strong_ordering operator<=>(const number_base& other) const;

		bool operator==(const number_base&) const;

		void set(const number_base&, std::size_t use_bits = -1);

		void set(bool, std::size_t pos);

		void resize(const std::size_t new_bits);

		std::size_t block_needed(std::size_t block_size) const;

		std::size_t padding_needed(std::size_t block_size) const;

		const unit_t& operator[](std::size_t size) const override;

		unit_t& operator[](std::size_t size) override;

		bool bit(std::size_t pos) const {
			return (data[pos / unit_bits] >> pos % unit_bits) & 1;
		}

		template<class V> requires std::is_integral_v<V>
		V value(std::size_t pos) const {
			if constexpr (sizeof(V) > unit_bytes) {
				V ret = 0;
				auto unit_pos = pos / (sizeof(V) / unit_bytes);
				for (std::size_t i = 0; i < sizeof(V) / unit_bytes && unit_pos + i < data_units(); ++i)
					ret |= data[unit_pos + i] << unit_bits * i;
				return ret;
			} else {
				auto unit_pos = pos / (unit_bytes / sizeof(V));
				return data[unit_pos] >> pos % (unit_bytes / sizeof(V)) * 8;
			}
		}

		void shrink();

		std::size_t msb_pos() const;
	};


	struct var_signed: var_unsigned {

		using var_unsigned::unit_t, var_unsigned::unit_bytes, var_unsigned::unit_bits, var_unsigned::var_unsigned;

		bool negative = false;

		var_signed(const var_unsigned& ref, bool neg = false)
				: var_unsigned(ref), negative(neg) {
		}

		template<class T> requires std::is_integral_v<T>
		var_signed(T val, std::size_t bits = sizeof(T) * 8)
				: var_unsigned(bits) {
			if (val < 0) {
				val = -val;
				negative = true;
			}
			for (std::size_t i = 0; i < data.size(); ++i)
				data[i] = i * unit_bytes < sizeof(T) ? val >> (unit_bits * i) : 0;
		}

		var_signed(const std::string_view bitstring, std::endian)
				: var_unsigned(bitstring.size() * 8) {
			auto it = bitstring.rbegin(), end = bitstring.rend();
			for (std::size_t i = 0; i < bits_ / 8 + (bits_ % 8 ? 1 : 0) && it != end; ++i)
				data[i / unit_bytes] |= static_cast<unit_t>(*it++ & 0xff) << 8 * (i % unit_bytes);
		}

		var_signed(const std::string_view hex)
				: var_unsigned{hex.size() * 4} {
			std::size_t t = 0;
			for (std::uint8_t ptr: std::ranges::reverse_view(hex))
				data[t / 2 / unit_bytes] |= hex_to_bits(ptr) << 4 * t % unit_bits, ++t;
		}

		var_signed operator+(const var_signed&) const;

		var_signed operator-(const var_signed&) const;

		var_signed operator*(const var_signed&) const;

		var_signed operator%(const var_signed&) const;

		var_signed operator-() const;

		std::strong_ordering operator<=>(const var_signed&) const;
	};
}

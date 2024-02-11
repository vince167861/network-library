#pragma once

#include "number_base.h"
#include <vector>
#include <ranges>

namespace leaf {

	struct big_unsigned : number_base {

		using number_base::unit_t;

		std::size_t bits() const override;

		std::size_t data_units() const override;

		static_assert(std::is_unsigned_v<unit_t>);

		std::vector<unit_t> data;

		big_unsigned()
				: bits_(0) {
		}

		template<class T> requires std::is_integral_v<T>
		big_unsigned(T val, std::optional<std::size_t> bits = std::nullopt)
				: big_unsigned(std::string_view{reinterpret_cast<const char *>(&val), sizeof(T)}, bits, std::endian::little) {
		}

		big_unsigned(const std::string_view bitstring, std::optional<std::size_t> bits = std::nullopt, std::endian = std::endian::big);

		big_unsigned(const number_base&);

		static big_unsigned from_hex(std::string_view hex);

		static big_unsigned from_little_endian_hex(std::string_view hex);

		big_unsigned operator+(const big_unsigned&) const;

		big_unsigned& operator+=(const big_unsigned&);

		big_unsigned operator-(const big_unsigned&) const;

		big_unsigned& operator-=(const big_unsigned&);

		big_unsigned operator*(const big_unsigned&) const;

		big_unsigned operator<<(std::size_t) const;

		big_unsigned& operator<<=(std::size_t);

		big_unsigned operator>>(std::size_t) const;

		big_unsigned& operator>>=(std::size_t);

		big_unsigned operator^(const big_unsigned&) const;

		big_unsigned& operator^=(const big_unsigned&);

		big_unsigned operator~() const;

		big_unsigned operator%(const big_unsigned& modulus) const;

		friend big_unsigned exp_mod(const big_unsigned& base, big_unsigned exp, const big_unsigned& modulus);

		std::strong_ordering operator<=>(const big_unsigned& other) const;

		bool operator==(const big_unsigned&) const;

		void set(const number_base&, std::size_t use_bits = -1);

		void set(bool, std::size_t pos);

		void resize(const std::size_t new_bits);

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

	protected:
		bool unsigned_add_(std::size_t pos, unit_t val, bool carry = false);

		std::size_t bits_;
	};

	inline struct casting_t {} from_unsigned_casting;


	struct var_signed: big_unsigned {

		using big_unsigned::big_unsigned, big_unsigned::unit_bytes, big_unsigned::unit_bits;

		bool negative = false;

		var_signed(casting_t, const big_unsigned& ref, bool neg = false)
				: big_unsigned(ref), negative(neg) {
		}

		template<class T> requires std::is_integral_v<T>
		var_signed(T val, std::optional<std::size_t> bits = std::nullopt)
				: big_unsigned(val < 0 ? -val : val, bits), negative(val < 0) {
		}

		var_signed(const std::string_view hex)
				: big_unsigned(0, hex.size() * 4) {
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

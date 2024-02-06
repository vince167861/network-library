#pragma once

#include "number_base.h"
#include <vector>

namespace leaf {

	class var_unsigned : public number_base {

		std::size_t bits_;

	public:
		using unit_t = uint32_t;

		std::size_t bits() const override;

		std::size_t data_units() const override;

		static_assert(std::is_unsigned_v<unit_t>);

		std::vector<unit_t> data;

	protected:
		bool unsigned_add_(std::size_t pos, unit_t val, bool carry = false);

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

		void set(const number_base&, std::size_t bits = -1);

		void set(bool, std::size_t pos);

		var_unsigned resize(std::size_t new_bits) const;

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
	};
}

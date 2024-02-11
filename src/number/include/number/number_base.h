#pragma once

#include "binary_object.h"

#include <cstdint>

namespace leaf {

	inline constexpr std::uintmax_t hex_to_bits(char c) {
		return '0' <= c && c <= '9' ? c - '0' : 'a' <= c && c <= 'f' ? c - 'a' + 10 : 'A' <= c && c <= 'F' ? c - 'A' + 10 : 0;
	}

	struct number_base: binary_object {

		using unit_t = std::uint32_t;

		static constexpr std::size_t unit_bytes = sizeof(unit_t);

		static constexpr std::size_t unit_bits = unit_bytes * 8;

		/**
		 * Access to n-th unit (counting from LSB).
		 * @return reference to n-th unit.
		 */
		virtual const unit_t& operator[](std::size_t) const = 0;

		/**
		 * Access to n-th unit (counting from LSB).
		 * @return reference to n-th unit.
		 */
		virtual unit_t& operator[](std::size_t) = 0;

		virtual std::size_t bits() const = 0;

		virtual std::size_t data_units() const = 0;

		/**
		 * Construct byte string in big-endian.
		 * @return byte string
		 */
		std::string to_bytestring(std::endian) const override;

		std::string to_string() const;

		virtual ~number_base() = default;
	};

	inline std::ostream& operator<<(std::ostream& s, const number_base& number) {
		s << number.to_string();
		return s;
	}
}

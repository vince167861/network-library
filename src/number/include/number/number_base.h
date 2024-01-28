#pragma once

#include "binary_object.h"

#include <cstdint>

namespace leaf {

	class number_base: public binary_object {
	public:
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
}

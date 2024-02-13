#pragma once
#include <string>
#include <cstdint>
#include <optional>

namespace leaf::experiment {

	struct big_unsigned: std::basic_string<std::uint8_t> {

		using base_t = std::basic_string<std::uint8_t>;

		using base_view_t = std::basic_string_view<std::uint8_t>;

		big_unsigned() = default;

		template<class T> requires std::is_integral_v<T>
		big_unsigned(T val, std::optional<std::size_t> bits = std::nullopt)
				: big_unsigned(base_view_t{reinterpret_cast<const std::uint8_t *>(&val), sizeof(T)}, bits, std::endian::little) {
		}

		big_unsigned(const base_view_t bitstring, std::optional<std::size_t> bits = std::nullopt, std::endian = std::endian::big);

		big_unsigned(const std::string_view hexstring, std::optional<std::size_t> bits = std::nullopt);

		big_unsigned& operator+=(const big_unsigned&);

		big_unsigned& operator-=(const big_unsigned&);

		big_unsigned& operator<<=(std::size_t);

		big_unsigned& operator>>=(std::size_t);

		big_unsigned& operator^=(const big_unsigned&);

		big_unsigned operator+(const big_unsigned& other) const {
			auto v = *this;
			v += other;
			return v;
		}

		big_unsigned operator-(const big_unsigned& other) const {
			auto v = *this;
			v -= other;
			return v;
		}

		big_unsigned operator*(const big_unsigned&) const;

		big_unsigned operator%(const big_unsigned& modulus) const;

		big_unsigned operator<<(const std::size_t shift) const {
			auto v = *this;
			v <<= shift;
			return v;
		}

		big_unsigned operator>>(const std::size_t shift) const {
			auto v = *this;
			v >>= shift;
			return v;
		}

		big_unsigned operator^(const big_unsigned& other) const {
			auto v = *this;
			v ^= other;
			return v;
		}

		big_unsigned operator~() const;

		std::size_t bit_used() const;

		void set_bit(std::size_t pos, bool value);

	private:
		std::size_t bits_;

		void resize_();
	};
}

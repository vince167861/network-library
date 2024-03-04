#pragma once
#include "byte_string.h"

struct big_unsigned: byte_string {

	big_unsigned() = default;

	big_unsigned(const big_unsigned& value, std::optional<std::size_t> bits) {
		resize(bits.value_or(value.bits_));
		set(value, bits);
	}

	template<class T> requires std::is_integral_v<T> && std::is_unsigned_v<T>
	big_unsigned(T val, std::optional<std::size_t> bits = std::nullopt)
			: big_unsigned(byte_string_view{reinterpret_cast<const std::uint8_t *>(&val), sizeof(T)}, bits, std::endian::native) {
	}

	big_unsigned(byte_string_view bitstring, std::optional<std::size_t> bits = std::nullopt, std::endian = std::endian::little);

	big_unsigned(std::string_view hexstring, std::optional<std::size_t> bits = std::nullopt);

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

	friend
	big_unsigned exp_mod(const big_unsigned& base, big_unsigned exp, const big_unsigned& modulus);

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

	std::strong_ordering operator<=>(const big_unsigned&) const;

	std::size_t bit_used() const;

	std::size_t bit_most() const {
		return bits_;
	}

	bool test(const std::size_t pos) const {
		return at(pos / 8) & 1 << pos % 8;
	}

	void set_bit(std::size_t pos, bool value);

	void set(const big_unsigned&, std::optional<std::size_t> bits = std::nullopt);

	void resize(const std::size_t bits) {
		if (bits_ == bits)
			return;
		bits_ = bits;
		resize_();
	}

	byte_string to_bytestring(std::endian) const;

	std::string to_string() const;

protected:
	std::size_t bits_{};

	void resize_();

	void sanitize_();
};


struct big_signed: big_unsigned {

	bool negative;

	template<class T> requires std::is_integral_v<T> && std::is_signed_v<T>
	big_signed(T val, std::optional<std::size_t> bits = std::nullopt)
			: big_signed(static_cast<std::make_unsigned_t<T>>(val < 0 ? -val : val), val < 0, bits) {
	}

	big_signed(big_unsigned value, bool negative = false)
			: negative(negative), big_unsigned(std::move(value)) {
	}

	big_signed& operator+=(const big_signed&);

	big_signed& operator-=(const big_signed&);

	big_signed operator+(const big_signed& other) const {
		big_signed R(*this);
		R += other;
		return R;
	}

	big_signed operator-(const big_signed& other) const {
		big_signed R(*this);
		R -= other;
		return R;
	}

	big_signed operator*(const big_signed& other) const {
		return {big_unsigned::operator*(other), negative != other.negative};
	}

	/**
	 * Modulo operator.
	 * @note This is *not* a remainder operator. Results of this operation have the
	 * same sign as the divisor.
	 */
	big_signed operator%(const big_signed&) const;

	big_signed operator-() const;

private:
	template<class T> requires std::is_integral_v<T> && std::is_unsigned_v<T>
	big_signed(T val, bool negative, std::optional<std::size_t> bits)
			: negative(negative), big_unsigned(byte_string_view{reinterpret_cast<const std::uint8_t *>(&val), sizeof(T)}, bits, std::endian::native) {
	}
};

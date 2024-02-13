#include "number/big_number.h"
#include "utils.h"
#include <ranges>

namespace leaf::experiment {

	inline constexpr std::uintmax_t hex_to_bits(char c) {
		return '0' <= c && c <= '9' ? c - '0' : 'a' <= c && c <= 'f' ? c - 'a' + 10 : 'A' <= c && c <= 'F' ? c - 'A' + 10 : 0;
	}

	big_unsigned::big_unsigned(const base_view_t bitstring, std::optional<std::size_t> bits, std::endian endian)
			: bits_(bits ? bits.value() : bitstring.size() * 8) {
		resize_();
		if (endian == std::endian::native)
			std::ranges::copy(bitstring, begin());
		else
			std::ranges::reverse_copy(bitstring, begin());
	}

	big_unsigned::big_unsigned(const std::string_view hexstring, std::optional<std::size_t> bits)
			: bits_(bits ? bits.value() : hexstring.size() * 4) {
		resize_();
		if constexpr (std::endian::native != std::endian::little)
			throw std::runtime_error{"unimplemented"};
		auto dst = begin();
		bool high = false;
		for (char c: std::ranges::reverse_view(hexstring)) {
			*dst |= hex_to_bits(c) << 4 * (high ? 1 : 0);
			if (high)
				++dst;
			high = !high;
		}
	}

	big_unsigned& big_unsigned::operator+=(const big_unsigned& other) {
		const auto this_ptr = reinterpret_cast<std::uint64_t *>(data());
		const auto other_ptr = reinterpret_cast<const std::uint64_t *>(other.data());
		const auto
				this_units = div_ceil(bits_, 64),
				other_units = div_ceil(other.bits_, 64),
				max = std::max(this_units, other_units);
		bits_ = std::max(bits_, other.bits_);
		resize_();
		bool carry = false;
		std::size_t i = 0;
		for (; i < max; ++i) {
			const auto old = this_ptr[i];
			if (i < other_units)
				this_ptr[i] += other_ptr[i];
			if (carry) {
				if (this_ptr[i] >= old)
					carry = false;
				this_ptr[i] += 1;
			}
			if (!carry)
				carry = this_ptr[i] < old;
		}
		if (carry) {
			++bits_;
			resize_();
			back() = 1;
		}
		return *this;
	}

	void big_unsigned::resize_() {
		reserve(div_ceil(bits_, 64) * 8);
		resize(div_ceil(bits_, 8));
		back() &= static_cast<std::uint8_t>(~0) >> divisible_requires(bits_, 8);
	}

	big_unsigned& big_unsigned::operator-=(const big_unsigned& other) {
		const auto this_ptr = reinterpret_cast<std::uint64_t *>(data());
		const auto other_ptr = reinterpret_cast<const std::uint64_t *>(other.data());
		const auto
				this_units = div_ceil(bits_, 64),
				other_units = div_ceil(other.bits_, 64),
				max = std::max(this_units, other_units);
		bits_ = std::max(bits_, other.bits_);
		resize_();
		bool borrow = false;
		for (std::size_t i = 0; i < max; ++i) {
			const auto old = this_ptr[i];
			this_ptr[i] -= (i < other_units ? other_ptr[i] : 0) + (borrow ? 1 : 0);
			borrow = this_ptr[i] > old || (borrow && this_ptr[i] == old);
		}
		return *this;
	}

	big_unsigned big_unsigned::operator*(const big_unsigned& other) const {
		big_unsigned ret(0, bits_ + other.bits_);
		const auto ret_ptr = reinterpret_cast<std::uint32_t*>(ret.data());
		const auto
				this_ptr = reinterpret_cast<const std::uint32_t*>(data()),
				other_ptr = reinterpret_cast<const std::uint32_t*>(other.data());
		const auto
				ret_units = div_ceil(ret.bits_, sizeof(std::uint32_t) * 8),
				this_units = div_ceil(bits_, sizeof(std::uint32_t) * 8),
				other_units = div_ceil(other.bits_, sizeof(std::uint32_t) * 8);
		bool finally_carry = false;
		for (std::size_t i = 0; i < this_units; ++i) {
			const std::uint64_t a = this_ptr[i];
			for (std::size_t j = 0; j < other_units && i + j < ret_units; ++j) {
				const std::uint64_t b = other_ptr[j];
				bool carry = false;
				auto pos = i + j;
				do {
					auto& dst = reinterpret_cast<std::uint64_t&>(ret_ptr[pos]), old = dst;
					dst += carry ? 1 : a * b;
					carry = dst < old;
					pos += 2;
				} while (carry && pos < ret_units);
				if (carry)
					finally_carry = true;
			}
		}
		if (finally_carry)
			ret.push_back(1);
		ret.bits_ = ret.bit_used();
		ret.resize_();
		return ret;
	}

	template<typename T>
	std::int8_t msb(const T val) {
		if (!val)
			return -1;
		std::int8_t pos = sizeof(T) * 8 - 1;
		auto mask = static_cast<T>(1) << pos;
		for (; !(val & mask); mask >>= 1, --pos);
		return pos;
	}

	big_unsigned big_unsigned::operator%(const big_unsigned& modulus) const {
		const auto this_bits = bit_used(), modulus_bits = modulus.bit_used();
		const auto cmp = this_bits <=> modulus_bits;
		if (std::is_lt(cmp))
			return *this;
		auto m_modulus = modulus;
		if (std::is_gt(cmp)) {
			m_modulus.resize(this_bits);
			m_modulus <<= this_bits - modulus_bits;
		}
		big_unsigned ret{*this};
		while (ret >= modulus) {
			if (ret >= m_modulus)
				ret -= m_modulus;
			m_modulus >>= 1;
		}
		ret.bits_ = modulus.bits_;
		ret.resize_();
		return ret;
	}

	big_unsigned& big_unsigned::operator<<=(const std::size_t shift) {
		if (shift > bits_) {
			for (auto& u: *this) u = 0;
			return *this;
		}
		const auto this_ptr = reinterpret_cast<std::uint64_t*>(data());
		const auto this_units = div_ceil(bits_, 64), shift_units = shift / 64, shift_bits = shift % 64;
		if (shift_units)
			this_ptr[this_units - 1] = 0;
		for (std::size_t i = 0; i < this_units; ++i) {
			const std::size_t dst = this_units - i - 1, src = dst - shift_units;
			if (const auto next = dst + 1; next < dst)
				this_ptr[next] |= src > dst ? 0 : this_ptr[src] >> 64 - shift_bits;
			this_ptr[dst] = src > dst ? 0 : this_ptr[src] << shift_bits;
		}
		resize_();
		return *this;
	}

	big_unsigned& big_unsigned::operator>>=(const std::size_t shift) {
		if (shift > bits_) {
			for (auto& u: *this) u = 0;
			return *this;
		}
		const auto this_ptr = reinterpret_cast<std::uint64_t*>(data());
		const auto this_units = div_ceil(bits_, 64), shift_units = shift / 64, shift_bits = shift % 64;
		if (shift_units)
			this_ptr[this_units - 1] = 0;
		for (std::size_t i = 0; i < this_units; ++i) {
			const std::size_t src = i + shift_units;
			if (const auto prev = src - 1; prev < this_units)
				this_ptr[prev] |= src < i ? ~0ull : this_ptr[src] << 64 - shift_bits;
			this_ptr[i] = this_ptr[src] >> shift_bits;
		}
		resize_();
		return *this;
	}

	big_unsigned& big_unsigned::operator^=(const big_unsigned& other) {
		if (!other.bits_)
			return *this;
		const auto
				this_units = div_ceil(bits_, 64),
				other_units = div_ceil(other.bits_, 64),
				min = std::min(this_units, other_units);
		const auto this_ptr = reinterpret_cast<std::uint64_t*>(data());
		const auto other_ptr = reinterpret_cast<const std::uint64_t*>(other.data());
		for (std::size_t i = 0; i < min; ++i)
			this_ptr[i] ^= other_ptr[i];
		resize_();
		return *this;
	}

	big_unsigned big_unsigned::operator~() const {
		if (!bits_)
			return {};
		big_unsigned val(0, bits_);
		const auto this_units = div_ceil(bits_, 64);
		const auto src = reinterpret_cast<const std::uint64_t*>(data());
		const auto dst = reinterpret_cast<std::uint64_t*>(val.data());
		for (std::size_t i = 0; i < this_units; ++i)
			dst[i] = ~src[i];
		return val;
	}

	std::size_t big_unsigned::bit_used() const {
		auto pos = find_last_not_of('\0');
		if (pos == npos)
			pos = size() - 1;
		return pos * 8 + msb(at(pos)) + 1;
	}

	void big_unsigned::set_bit(std::size_t pos, bool value) {
		const std::uint8_t mask = 1 << pos % 8;
		if (value)
			at(pos / 8) |= mask;
		else
			at(pos / 8) &= ~mask;
	}
}

#include "number/big_number.h"
#include "utils.h"
#include <format>
#include <ranges>
#include <utility>

namespace leaf {

	inline constexpr std::uintmax_t hex_to_bits(char c) {
		return '0' <= c && c <= '9' ? c - '0' : 'a' <= c && c <= 'f' ? c - 'a' + 10 : 'A' <= c && c <= 'F' ? c - 'A' + 10 : 0;
	}

	big_unsigned::big_unsigned(const byte_string_view bitstring, std::optional<std::size_t> bits, std::endian endian) {
		resize(bits.value_or(bitstring.size() * 8));
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

	bool add(std::uint64_t* dst, const std::size_t dst_bits, const std::uint64_t* src, const std::size_t src_bits) {
		const auto dst_size = div_ceil(dst_bits, 64), src_size = div_ceil(src_bits, 64);
		bool carry = false;
		for (std::size_t i = 0; i < dst_size; ++i) {
			const auto a = i == dst_size - 1 && dst_bits % 64 ? dst[i] & ~(~0ull << dst_bits % 64) : dst[i];
			const auto b = i == src_size - 1 && src_bits % 64 ? src[i] & ~(~0ull << src_bits % 64) : i < src_size ? src[i] : 0;
			dst[i] = a + b + (carry ? 1 : 0);
			carry = dst[i] < a || carry && dst[i] == a;
		}
		return carry;
	}

	big_unsigned& big_unsigned::operator+=(const big_unsigned& other) {
		const auto dst_bits = std::exchange(bits_, std::max(bits_, other.bits_));
		resize_();
		if (add(
				reinterpret_cast<std::uint64_t*>(data()), dst_bits,
				reinterpret_cast<const std::uint64_t*>(other.data()), other.bits_)) {
			++bits_;
			resize_();
			back() = 1;
		}
		return *this;
	}

	bool subtract(std::uint64_t* dst, const std::size_t dst_bits, const std::uint64_t* src, const std::size_t src_bits) {
		const auto dst_size = div_ceil(dst_bits, 64), src_size = div_ceil(src_bits, 64);
		bool borrow = false;
		for (std::size_t i = 0; i < dst_size; ++i) {
			const auto a = i == dst_size - 1 && dst_bits % 64 ? dst[i] & ~(~0ull << dst_bits % 64) : dst[i];
			const auto b = i == src_size - 1 && src_bits % 64 ? src[i] & ~(~0ull << src_bits % 64) : i < src_size ? src[i] : 0;
			dst[i] = a - b - (borrow ? 1 : 0);
			borrow = dst[i] > a || borrow && dst[i] == a;
		}
		return borrow;
	}

	big_unsigned& big_unsigned::operator-=(const big_unsigned& other) {
		const auto dst_bits = std::exchange(bits_, std::max(bits_, other.bits_));
		resize_();
		subtract(
				reinterpret_cast<std::uint64_t *>(data()), dst_bits,
				reinterpret_cast<const std::uint64_t *>(other.data()), other.bits_);
		return *this;
	}

	big_unsigned big_unsigned::operator*(const big_unsigned& other) const {
		big_unsigned ret(0u, bits_ + other.bits_);
		const auto ret_ptr = reinterpret_cast<std::uint32_t*>(ret.data());
		const auto
				this_ptr = reinterpret_cast<const std::uint32_t*>(data()),
				other_ptr = reinterpret_cast<const std::uint32_t*>(other.data());
		const auto
				ret_units = div_ceil(ret.bits_, 32),
				this_units = div_ceil(bits_, 32),
				other_units = div_ceil(other.bits_, 32);
		bool finally_carry = false;
		for (std::size_t i = 0; i < this_units; ++i) {
			const std::uint64_t a = i == this_units - 1 && bits_ % 32 ? this_ptr[i] & ~(~0ull << bits_ % 32) : this_ptr[i];
			for (std::size_t j = 0; j < other_units && i + j < ret_units; ++j) {
				const std::uint64_t b = j == other_units - 1 && other.bits_ % 32 ? other_ptr[j] & ~(~0ull << other.bits_ % 32) : other_ptr[j];
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

	big_unsigned exp_mod(const big_unsigned& base, big_unsigned exp, const big_unsigned& modulus) {
		const big_unsigned zero(0u);
		big_unsigned ret(1u);
		auto new_base = base % modulus;
		while (exp > zero && ret > zero) {
			if (exp.test(0))
				ret = ret * new_base % modulus;
			exp >>= 1;
			new_base = new_base * new_base % modulus;
		}
		return ret;
	}

	big_unsigned& big_unsigned::operator<<=(const std::size_t shift) {
		if (!shift)
			return *this;
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
			if (const auto next = dst + 1; next > dst && next < this_units && shift_bits)
				this_ptr[next] |= src > dst ? 0 : this_ptr[src] >> 64 - shift_bits;
			this_ptr[dst] = src > dst ? 0 : this_ptr[src] << shift_bits;
		}
		sanitize_();
		return *this;
	}

	big_unsigned& big_unsigned::operator>>=(const std::size_t shift) {
		if (!shift)
			return *this;
		if (shift > bits_) {
			for (auto& u: *this) u = 0;
			return *this;
		}
		const auto __ptr = reinterpret_cast<std::uint64_t*>(data());
		const auto __s = div_ceil(bits_, 64), __e = bits_ % 64, __u = shift / 64, __b = shift % 64;
		for (std::size_t i = 0; i < __s; ++i) {
			if (i >= __s - __u) {
				__ptr[i] = 0;
				continue;
			}
			const std::size_t __src = i + __u;
			std::uint64_t __v = (__src == __s - 1 && __e ? __ptr[__src] & ~(~0ull << __e) : __ptr[__src]) >> __b;
			if (const auto __n = __src + 1; __b && __n < __s)
				__v |= __ptr[__n] << 64 - __b;
			__ptr[i] = __v;
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
		big_unsigned val(0u, bits_);
		const auto this_units = div_ceil(bits_, 64);
		const auto src = reinterpret_cast<const std::uint64_t*>(data());
		const auto dst = reinterpret_cast<std::uint64_t*>(val.data());
		for (std::size_t i = 0; i < this_units; ++i)
			dst[i] = ~src[i];
		return val;
	}

	std::size_t big_unsigned::bit_used() const {
		auto pos = find_last_not_of('\0');
		return pos == npos ? 0 : pos * 8 + msb(at(pos)) + 1;
	}

	void big_unsigned::set_bit(std::size_t pos, bool value) {
		const std::uint8_t mask = 1 << pos % 8;
		if (value)
			at(pos / 8) |= mask;
		else
			at(pos / 8) &= ~mask;
	}

	void big_unsigned::set(const big_unsigned& value, std::optional<std::size_t> bits) {
		const auto use_bits = bits ? bits.value() : value.bits_;
		const auto use_units = use_bits / 64;
		const auto dst_ptr = reinterpret_cast<std::uint64_t*>(data());
		const auto src_ptr = reinterpret_cast<const std::uint64_t*>(value.data());
		for (std::size_t i = 0; i < use_units; ++i)
			dst_ptr[i] = i < use_units ? src_ptr[i] : 0;
		if (const auto excess = use_bits % 64) {
			auto& msu = dst_ptr[use_units];
			const std::int64_t val = use_units < div_ceil(value.bits_, 64) ? src_ptr[use_units] & ~(~0ull << excess) : 0;
			msu = msu & ~0ull << excess | val;
		}
	}

	std::strong_ordering big_unsigned::operator<=>(const big_unsigned& other) const {
		const auto
				__pa = reinterpret_cast<const std::uint64_t*>(data()),
				__pb = reinterpret_cast<const std::uint64_t*>(other.data());
		const auto __ua = div_ceil(bits_, 64), __ub = div_ceil(other.bits_, 64), cmn_units = std::min(__ub, __ua);
		if (__ua > __ub) {
			if (__ub)
				for (auto i = __ua - 1; i >= __ub; --i)
					if (__pa[i]) return std::strong_ordering::greater;
		} else {
			if (__ua)
				for (auto i = __ub - 1; i >= __ua; --i)
					if (__pb[i]) return std::strong_ordering::less;
		}
		if (cmn_units)
			for (auto i = cmn_units - 1; i < cmn_units; --i) {
				const auto a = i == __ua - 1 && bits_ % 64 ? __pa[i] & ~(~0ull << bits_ % 64) : __pa[i];
				const auto b = i == __ub - 1 && other.bits_ % 64 ? __pb[i] & ~(~0ull << other.bits_ % 64) : __pb[i];
				const auto r = a <=> b;
				if (std::is_neq(r))
					return r;
			}
		else if (__ua)
			return (__ua == 1 && bits_ % 64 ? __pa[0] & ~(~0ull << bits_ % 64) : __pa[0]) ? std::strong_ordering::greater : std::strong_ordering::equal;
		else if (__ub)
			return (__ub == 1 && other.bits_ % 64 ? __pb[0] & ~(~0ull << bits_ % 64) : __pb[0]) ? std::strong_ordering::less : std::strong_ordering::equal;
		return std::strong_ordering::equal;
	}

	void big_unsigned::resize_() {
		reserve(div_ceil(bits_, 64) * 8);
		byte_string::resize(div_ceil(bits_, 8));
		sanitize_();
	}

	void big_unsigned::sanitize_() {
		std::ranges::fill_n(end(), capacity() - size(), 0);
		back() &= static_cast<std::uint8_t>(~0) >> divisible_requires(bits_, 8);
	}

	byte_string big_unsigned::to_bytestring(std::endian endian) const {
		std::string str(size(), 0);
		if (endian == std::endian::native)
			std::ranges::copy(*this, str.begin());
		else
			std::ranges::reverse_copy(*this, str.begin());
		return endian == std::endian::native ? static_cast<byte_string>(*this) : byte_string(rbegin(), rend());
	}

	std::string big_unsigned::to_string() const {
		std::string str;
		if (std::endian::native == std::endian::little) for (auto c: std::views::reverse(*this))
			str += std::format("{:02x}", c);
		else for (auto c: *this)
			str += std::format("{:02x}", c);
		return str;
	}

	big_signed& big_signed::operator+=(const big_signed& other) {
		resize(std::max(bits_, other.bits_) + 1);
		const auto dst = reinterpret_cast<std::uint64_t*>(data());
		if (negative == other.negative) {
			if (add(dst, bits_, reinterpret_cast<const std::uint64_t*>(other.data()), other.bits_)) {
				++bits_;
				resize_();
				back() = 1;
			}
		} else {
			if (subtract(dst, bits_, reinterpret_cast<const std::uint64_t*>(other.data()), other.bits_)) {
				for (auto& c: *this)
					c = ~c;
				const std::uint64_t one = 1;
				add(dst, bits_, &one, 1);
				negative = !negative;
			}
		}
		resize(bit_used());
		return *this;
	}

	big_signed& big_signed::operator-=(const big_signed& other) {
		resize(std::max(bits_, other.bits_) + 1);
		const auto dst = reinterpret_cast<std::uint64_t*>(data());
		if (negative != other.negative) {
			if (add(dst, bits_, reinterpret_cast<const std::uint64_t*>(other.data()), other.bits_)) {
				++bits_;
				resize_();
				back() = 1;
			}
		} else {
			if (subtract(dst, bits_, reinterpret_cast<const std::uint64_t*>(other.data()), other.bits_)) {
				for (auto& c: *this)
					c = ~c;
				const std::uint64_t one = 1;
				add(dst, bits_, &one, 1);
				negative = !negative;
			}
		}
		resize(bit_used());
		return *this;
	}

	big_signed big_signed::operator-() const {
		auto R{*this};
		R.negative = !R.negative;
		return R;
	}

	big_signed big_signed::operator%(const big_signed& __dr) const {
		big_signed __v(big_unsigned::operator%(__dr), negative);
		if (negative != __dr.negative)
			__v += __dr;
		return __v;
	}
}

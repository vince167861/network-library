#include "number/flexible.h"

#include <ranges>

namespace leaf {

	bool var_unsigned::unsigned_add_(std::size_t pos, unit_t val, bool carry) {
		auto& field = data[pos], ori = field;
		field += val;
		if (carry) {
			const bool new_carry = field < ori || ~field == 0;
			field += 1;
			return new_carry;
		}
		return field < ori;
	}

	var_unsigned var_unsigned::from_bytes(const std::string_view bytes) {
		auto ptr = bytes.rbegin();
		var_unsigned ret(bytes.size() * 8);
		for (std::size_t i = 0; i < ret.bits_ / 8 + (ret.bits_ % 8 ? 1 : 0) && ptr != bytes.rend(); ++i)
			ret.data[i / unit_bytes] |= static_cast<unit_t>(*ptr++ & 0xff) << 8 * (i % unit_bytes);
		return ret;
	}

	var_unsigned var_unsigned::from_little_endian_bytes(const std::string_view bytes) {
		auto ptr = bytes.begin();
		var_unsigned ret(bytes.size() * 8);
		for (std::size_t i = 0; i < ret.bits_ / 8 + (ret.bits_ % 8 ? 1 : 0) && ptr != bytes.end(); ++i)
			ret.data[i / unit_bytes] |= static_cast<uint8_t>(*ptr++ & 0xff) << 8 * (i % unit_bytes);
		return ret;
	}

	var_unsigned var_unsigned::from_hex(std::string_view hex) {
		var_unsigned ret(hex.size() * 4);
		std::size_t t = 0;
		for (char ptr: std::ranges::reverse_view(hex))
			ret[t / 2 / unit_bytes] |= hex_to_bits(ptr) << 4 * t % unit_bits, ++t;
		return ret;
	}

	var_unsigned var_unsigned::from_little_endian_hex(std::string_view hex) {
		var_unsigned ret(hex.size() * 4);
		std::size_t t = 0;
		for (char c: hex)
			(ret[t / 2 / unit_bytes] |= hex_to_bits(c) << ((t / 2 % unit_bytes) * 8 + (1 - t % 2) * 4)), ++t;
		return ret;
	}

	var_unsigned::var_unsigned(std::size_t bits, unit_t val)
			: bits_(bits), data(bits / unit_bits + (bits % unit_bits ? 1 : 0), val) {
	}

	var_unsigned& var_unsigned::operator+=(const var_unsigned& other) {
		auto min_len = std::min(data_units(), other.data_units());
		bool carry = false;
		for (size_t i = 0; i < min_len; ++i)
			carry = unsigned_add_(i, other.data[i], carry);
		return *this;
	}

	var_unsigned var_unsigned::operator+(const var_unsigned& other) const {
		var_unsigned ret(*this);
		ret += other;
		return ret;
	}

	var_unsigned& var_unsigned::operator-=(const var_unsigned& other) {
		bool borrow = false;
		for (size_t i = 0; i < data_units(); ++i) {
			auto this_data = data[i];
			data[i] -= other.data[i] + (borrow ? 1 : 0);
			borrow = data[i] > this_data || (borrow && data[i] == this_data);
		}
		return *this;
	}

	var_unsigned var_unsigned::operator-(const var_unsigned& other) const {
		var_unsigned ret(*this);
		ret -= other;
		return ret;
	}

	var_unsigned var_unsigned::operator*(const var_unsigned& other) const {
		auto return_bits = bits_ + other.bits_;
		var_unsigned ret(return_bits);
		auto return_units = ret.data_units();
		for (size_t i = 0; i < data_units(); ++i) {
			uint64_t a = data[i];
			for (std::size_t j = 0; j < other.data_units() && i + j < return_units; ++j) {
				uint64_t b = other.data[j];
				auto r = a * b;
				bool carry = false;
				for (auto pos = i + j;
					 pos < return_units && (r || carry);
					 r >>= unit_bits, ++pos)
					carry = ret.unsigned_add_(pos, r, carry);
			}
		}
		return ret;
	}

	var_unsigned& var_unsigned::operator<<=(std::size_t shift) {
		if (shift > data_units() * unit_bits)
			for (auto& u: data) u = 0;
		else {
			auto shift_units = shift / (unit_bytes << 3);
			shift %= unit_bytes << 3;
			for (std::size_t i = 0; i < data_units(); ++i) {
				auto j = data_units() - i - 1;
				auto this_data = data[j];
				data[j] = 0;
				if (shift_units <= j)
					data[j] = (shift_units == 0 ? this_data : data[j - shift_units]) << shift;
				if (shift_units <= j - 1 && shift > 0 && j > 0)
					data[j] |= data[j - 1 - shift_units] >> (unit_bits - shift);
			}
		}
		return *this;
	}

	var_unsigned var_unsigned::operator<<(std::size_t shift) const {
		var_unsigned ret{*this};
		ret <<= shift;
		return ret;
	}

	var_unsigned& var_unsigned::operator>>=(std::size_t shift) {
		if (shift > data_units() * unit_bits)
			for (auto& u: data) u = 0;
		else {
			auto shift_units = shift / unit_bits;
			shift %= unit_bits;
			for (std::size_t i = 0; i < data_units(); ++i) {
				auto this_data = data[i];
				data[i] = 0;
				if (i + shift_units < data_units())
					data[i] = (shift_units == 0 ? this_data : data[i + shift_units]) >> shift;
				if (i + 1 + shift_units < data_units() && shift > 0)
					data[i] |= data[i + 1 + shift_units] << (unit_bits - shift);
			}
		}
		return *this;
	}

	var_unsigned var_unsigned::operator>>(std::size_t shift) const {
		var_unsigned ret{*this};
		ret >>= shift;
		return ret;
	}

	var_unsigned& var_unsigned::operator^=(const var_unsigned& other) {
		for (std::size_t i = 0; i < data_units(); ++i)
			data[i] ^= other.data[i];
		return *this;
	}

	var_unsigned var_unsigned::operator^(const var_unsigned& other) const {
		var_unsigned ret{*this};
		ret ^= other;
		return ret;
	}

	var_unsigned var_unsigned::operator~() const {
		var_unsigned ret{*this};
		for (auto& u: ret.data)
			u = ~u;
		return ret;
	}

	std::size_t var_unsigned::block_needed(std::size_t block_size) const {
		return bits_ / block_size + (bits_ % block_size ? 1 : 0);
	}

	std::size_t var_unsigned::padding_needed(std::size_t block_size) const {
		return bits_ % block_size ? block_size - bits_ % block_size : 0;
	}

	std::strong_ordering var_unsigned::operator<=>(const number_base& other) const {
		if (data_units() > other.data_units()) {
			for (auto i = data_units() - 1; i >= other.data_units(); --i)
				if (data[i] > 0) return std::strong_ordering::greater;
		} else {
			for (auto i = other.data_units() - 1; i >= data_units(); --i)
				if (other[i] > 0) return std::strong_ordering::less;
		}

		for (auto i = std::min(other.data_units(), data_units()) - 1; i > 0; --i) {
			auto r = data[i] <=> other[i];
			if (std::is_neq(r)) return r;
		}
		return data[0] <=> other[0];
	}

	std::size_t var_unsigned::bits() const {
		return bits_;
	}

	std::size_t var_unsigned::data_units() const {
		return data.size();
	}

	const number_base::unit_t& var_unsigned::operator[](std::size_t size) const {
		return data[size];
	}

	void var_unsigned::set(const number_base& other, const std::size_t bits) {
		auto other_bits = std::min(other.bits(), bits);
		for (std::size_t i = 0; i < other_bits / unit_bits; ++i)
			data[i] = other[i];
		if (const auto excess = other_bits % unit_bits) {
			auto& msu = data[other_bits / unit_bits];
			const unit_t val = other[other_bits / unit_bits] & ~(~0 << excess);
			msu = msu & ~0 << excess | val;
		}
	}

	number_base::unit_t& var_unsigned::operator[](std::size_t size) {
		return data[size];
	}

	bool var_unsigned::operator==(const number_base& other) const {
		return std::is_eq(*this <=> other);
	}

	var_unsigned var_unsigned::resize(const std::size_t new_bits) const {
		var_unsigned ret(new_bits);
		ret.set(*this, new_bits);
		return ret;
	}

	var_unsigned::var_unsigned(const number_base& ref)
			: var_unsigned(ref.bits()) {
		for (std::size_t i = 0; i < data.size(); ++i)
			data[i] = i < ref.data_units() ? ref[i] : 0;
	}

	void var_unsigned::set(const bool val, const std::size_t pos) {
		const auto byte = pos / unit_bits, bit = pos % unit_bits;
		const unit_t mask = 1 << bit;
		if (val)
			data[byte] |= mask;
		else
			data[byte] &= ~mask;
	}

}

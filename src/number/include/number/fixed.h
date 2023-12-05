#pragma once

#include "number_base.h"

namespace leaf {

	constexpr unsigned long long hex_to_bits(char c) {
		return '0' <= c && c <= '9' ? c - '0' : 'a' <= c && c <= 'f' ? c - 'a' + 10 : 'A' <= c && c <= 'F' ? c - 'A' + 10 : 0;
	}

	template<class T>
	constexpr T abs(const T& val) {
		return val >= 0 ? val : -val;
	}


	template<std::size_t B>
	class fixed_unsigned: public number_base {

		template<std::size_t D>
		friend class fixed_unsigned;

		static constexpr std::size_t data_units_ = B / unit_bits + (B % unit_bits == 0 ? 0 : 1);

	public:
		constexpr size_t data_units() const override {
			return data_units_;
		}

		using data_t = unit_t[data_units_];

		static_assert(std::is_unsigned_v<unit_t>); // unit_t(-1) is maximum
		static_assert(B > 0);
		static_assert(unit_bytes <= sizeof(uint64_t) / 2);

	protected:
		bool unsigned_add_(std::size_t pos, unit_t val, bool carry = false) {
			auto& field = data[pos], ori = field;
			field += val;
			if (carry) {
				bool new_carry = field < ori || ~field == 0;
				field += 1;
				return new_carry;
			}
			return field < ori;
		}

	public:
		data_t data{};

		constexpr fixed_unsigned() {
			for (auto& u: data)
				u = 0;
		}

		template<class T> requires std::is_integral_v<T>
		constexpr fixed_unsigned(T val) { // NOLINT(*-explicit-constructor)
			for (std::size_t i = 0; i < data_units_; ++i)
				data[i] = i * unit_bytes < sizeof(T) ? val >> (unit_bits * i) : 0;
		}

		constexpr fixed_unsigned(const number_base& ref) { // NOLINT(*-explicit-constructor)
			for (std::size_t i = 0; i < data_units_; ++i)
				data[i] = i < ref.data_units() ? ref[i] : 0;
		}

		template<std::size_t D>
		explicit constexpr fixed_unsigned(const char (&hex)[D]) {
			for (std::size_t i = 0; i < D - 1; ++i) {
				if (i % (unit_bytes * 2) == 0)
					data[i / (unit_bytes * 2)] = 0;
				data[i / (unit_bytes * 2)] |= hex_to_bits(hex[D - i - 2]) << (i % (unit_bytes * 2) * 4);
			}
			auto orig_N = (D - 1) / 2 + (D - 1) % 2;
			for (std::size_t i = orig_N / unit_bytes + (orig_N % unit_bytes == 0 ? 0 : 1); i < data_units_; ++i)
				data[i] = 0;
		}

		constexpr fixed_unsigned(std::string_view hex) { // NOLINT(*-explicit-constructor)
			for (std::size_t i = 0; i < hex.size(); ++i) {
				if (i % (unit_bytes * 2) == 0)
					data[i / (unit_bytes * 2)] = 0;
				data[i / (unit_bytes * 2)] |= hex_to_bits(hex.at(hex.size() - i - 1)) << (i % (unit_bytes * 2) * 4);
			}
			auto orig_N = hex.size() / 2 + hex.size() % 2;
			for (std::size_t i = orig_N / unit_bytes + (orig_N % unit_bytes == 0 ? 0 : 1); i < data_units_; ++i)
				data[i] = 0;
		}

		template<std::size_t A>
		constexpr fixed_unsigned& operator+=(const fixed_unsigned<A>& other) {
			constexpr auto min_len = std::min(data_units_, fixed_unsigned<A>::data_units_);
			bool carry = false;
			for (size_t i = 0; i < min_len; ++i)
				carry = unsigned_add_(i, other.data[i], carry);
			return *this;
		}

		template<std::size_t A, std::size_t R = std::max(A, B) + 1>
		constexpr fixed_unsigned<R> operator+(const fixed_unsigned<A>& other) const {
			fixed_unsigned<R> ret{*this};
			ret += other;
			return ret;
		}

		template<std::size_t D>
		constexpr auto operator*(const fixed_unsigned<D>& other) const {
			using return_t = fixed_unsigned<D + B>;
			return_t ret;
			for (size_t i = 0; i < data_units_; ++i) {
				uint64_t a = data[i];
				for (std::size_t j = 0; j < fixed_unsigned<D>::data_units_ && i + j < return_t::data_units_; ++j) {
					uint64_t b = other.data[j];
					auto r = a * b;
					bool carry = false;
					for (auto pos = i + j;
							pos < return_t::data_units_ && (r || carry);
							r >>= unit_bits, ++pos)
						carry = ret.unsigned_add_(pos, r, carry);
				}
			}
			return ret;
		}

		constexpr fixed_unsigned& operator-=(const fixed_unsigned& other) {
			bool borrow = false;
			for (size_t i = 0; i < data_units_; ++i) {
				auto this_data = data[i];
				data[i] -= other.data[i] + (borrow ? 1 : 0);
				borrow = data[i] > this_data || (borrow && data[i] == this_data);
			}
			return *this;
		}

		template<std::size_t D, std::size_t R = std::max(D, B)>
		constexpr fixed_unsigned<R> operator-(const fixed_unsigned<D>& other) const {
			fixed_unsigned<R> ret{*this};
			ret -= other;
			return ret;
		}

		constexpr fixed_unsigned& operator<<=(std::size_t shift) {
			if (shift > data_units_ * unit_bytes * 8)
				for (auto& u: data) u = 0;
			else {
				auto shift_units = shift / (unit_bytes << 3);
				shift %= unit_bytes << 3;
				for (std::size_t i = 0; i < data_units_; ++i) {
					auto j = data_units_ - i - 1;
					auto this_data = data[j];
					data[j] = 0;
					if (shift_units <= j)
						data[j] = (shift_units == 0 ? this_data : data[j - shift_units]) << shift;
					if (shift_units <= j - 1 && shift > 0 && j > 0)
						data[j] |= data[j - 1 - shift_units] >> (unit_bytes * 8 - shift);
				}
			}
			return *this;
		}

		constexpr fixed_unsigned operator<<(std::size_t shift) const {
			if (shift > data_units_ * unit_bytes * 8)
				return {};
			fixed_unsigned ret{*this};
			ret <<= shift;
			return ret;
		}

		constexpr fixed_unsigned operator>>=(std::size_t shift) {
			if (shift > data_units_ * unit_bits)
				for (auto& u: data) u = 0;
			else {
				auto shift_units = shift / unit_bits;
				shift %= unit_bits;
				for (std::size_t i = 0; i < data_units_; ++i) {
					auto this_data = data[i];
					data[i] = 0;
					if (i + shift_units < data_units_)
						data[i] = (shift_units == 0 ? this_data : data[i + shift_units]) >> shift;
					if (i + 1 + shift_units < data_units_ && shift > 0)
						data[i] |= data[i + 1 + shift_units] << (unit_bits - shift);
				}
			}
			return *this;
		}

		constexpr fixed_unsigned operator>>(std::size_t shift) const {
			if (shift > data_units_ * unit_bytes * 8)
				return {};
			fixed_unsigned ret{*this};
			ret >>= shift;
			return ret;
		}

		constexpr fixed_unsigned& operator^=(const fixed_unsigned& other) {
			for (std::size_t i = 0; i < data_units_; ++i)
				data[i] ^= other.data[i];
			return *this;
		}

		constexpr fixed_unsigned operator^(const fixed_unsigned& other) const {
			fixed_unsigned ret{*this};
			ret ^= other;
			return ret;
		}

		fixed_unsigned operator~() const {
			fixed_unsigned ret{*this};
			for (auto& u: ret.data)
				u = ~u;
			return ret;
		}

		template<std::size_t D>
		fixed_unsigned<D> operator%(const fixed_unsigned<D>& modulus) const {
			fixed_unsigned ret{*this};
			std::size_t msb_at = data_units_ - 1, processed_bits = 0, start_shift = modulus.data_units_ - 1;
			fixed_unsigned expanded_modulus{modulus};
			while (start_shift && expanded_modulus.data[start_shift] == 0)
				--start_shift;
			expanded_modulus <<= (data_units_ - start_shift - 1) * unit_bits;
			while (ret >= modulus) {
				while (ret >= expanded_modulus)
					ret -= expanded_modulus;
				expanded_modulus >>= 1;
				if (++processed_bits % (unit_bytes * 8) == 0)
					--msb_at;
			}
			return {ret};
		}

		template<std::size_t D, std::size_t P>
		friend fixed_unsigned<P> exp_mod(const fixed_unsigned& base, fixed_unsigned<D> exp, const fixed_unsigned<P>& modulus) {
			fixed_unsigned<P> ret{1};
			auto&& new_base = base % modulus;
			while (exp > fixed_unsigned(0) && ret > fixed_unsigned(0)) {
				if (exp.data[0] % 2 == 1)
					ret = ret * new_base % modulus;
				exp >>= 1;
				new_base = new_base * new_base % modulus;
			}
			return ret;
		}

		template<std::size_t D>
		std::strong_ordering operator<=>(const fixed_unsigned<D>& other) const {
			if constexpr (data_units_ > fixed_unsigned<D>::data_units_) {
				for (auto i = data_units_ - 1; i >= fixed_unsigned<D>::data_units_; --i)
					if (data[i] > 0) return std::strong_ordering::greater;
			} else {
				for (auto i = fixed_unsigned<D>::data_units_ - 1; i >= data_units_; --i)
					if (other.data[i] > 0) return std::strong_ordering::less;
			}

			for (auto i = std::min(fixed_unsigned<D>::data_units_, data_units_) - 1; i > 0; --i) {
				auto r = data[i] <=> other.data[i];
				if (r != 0) return r;
			}
			return data[0] <=> other.data[0];
		}

		template<std::size_t D>
		bool operator==(const fixed_unsigned<D>& other) const {
			return std::is_eq(*this <=> other);
		}

		template<std::size_t D>
		void set(const fixed_unsigned<D>& other, std::size_t pos = 0) {
			static_assert(B >= D);
			for (std::size_t i = 0; i < D / unit_bits; ++i)
				data[i + pos] = other.data[i];
			auto b = D % unit_bits;
			if (b) {
				auto& msu = data[D / unit_bits + pos];
				unit_t val = other.data[D / unit_bits] & ~(static_cast<unit_t>(-1) << b);
				msu = (msu & static_cast<unit_t>(-1) << b) | val;
			}
		}

		void set(std::size_t pos, bool val) {
			auto byte = pos / unit_bits, bit = pos % unit_bits;
			unit_t mask = 1 << bit;
			if (val)
				data[byte] |= mask;
			else
				data[byte] &= ~mask;
		}

		constexpr bool bit(std::size_t pos) const {
			return (data[pos / unit_bits] >> pos % unit_bits) & 1;
		}

		template<class V> requires std::is_integral_v<V>
		V value(std::size_t pos) const {
			auto unit_pos = pos / (unit_bytes / sizeof(V));
			return data[unit_pos] >> pos % (unit_bytes / sizeof(V)) * 8;
		}

		/**
		 * Construct fixed_unsigned from byte string in big-endian.
		 * @return fixed_unsigned
		 */
		static fixed_unsigned from_bytes(std::string_view bytes) {
			auto ptr = bytes.rbegin();
			fixed_unsigned ret;
			for (std::size_t i = 0; i < B / 8 + (B % 8 ? 0 : 1) && ptr != bytes.rend(); ++i)
				ret.data[i / unit_bytes] |= unit_t(static_cast<uint8_t>(*(ptr++))) << (i % unit_bytes) * 8;
			return ret;
		}

		unit_t& operator[](std::size_t size) override {
			return data[size];
		}

		constexpr const unit_t& operator[](std::size_t size) const override {
			return data[size];
		}

		constexpr size_t bits() const override {
			return B;
		}
	};

	template<std::size_t D>
	fixed_unsigned(const char (&hex)[D]) -> fixed_unsigned<(D - 1) * 4>;

	template<class V> requires std::is_integral_v<V>
	fixed_unsigned(V) -> fixed_unsigned<sizeof(V) * 8>;


	template<std::size_t bits>
	class fixed_signed: public fixed_unsigned<bits> {

		using base = fixed_unsigned<bits>;
		using typename base::unit_t;
		using base::unit_bytes, base::unit_bits;

		template<std::size_t D>
		friend class fixed_signed;

	public:

		bool negative = false;

		bool is_negative() const {
			// return data[data_units - 1] >> (unit_bits - 1) & 1;
			return negative;
		}

		using base::fixed_unsigned;

		/**
		 * Casts fixed_unsigned to number.
		 * Uses `bits - 1` to determine if number is negative.
		 * All bits above `N` are cleared.
		 */
		template<std::size_t D>
		constexpr fixed_signed(const fixed_unsigned<D>& ref, bool neg = false)
				: fixed_unsigned<bits>(ref), negative(neg) {
		}

		template<std::size_t D>
		constexpr fixed_signed(const fixed_signed<D>& ref)
				: fixed_unsigned<bits>(ref), negative(ref.negative) {
		}

		template<class V> requires std::is_integral_v<V>
		constexpr fixed_signed(V val)		// NOLINT(*-explicit-constructor)
				: fixed_unsigned<bits>(leaf::abs(val)), negative(val < 0) {
			// TODO: clear excess bits
		}

		template<std::size_t D, auto R = std::max(D, bits) + 1>
		constexpr fixed_signed<R> operator+(const fixed_signed<D>& other) const {
			if (negative)
				return other - (- *this);
			if (other.negative)
				return operator-(- other);
			return base::operator+(other);
		}

		template<std::size_t D, auto R = std::max(D, bits) + 1>
		constexpr fixed_signed<R> operator-(const fixed_signed<D>& other) const {
			if (negative && other.negative)
				return (- other) - (- *this);
			if (negative)
				return - ((- *this) + other);
			if (other.negative)
				return *this + (- other);
			if (*this < other)
				return {static_cast<fixed_signed<D>::base>(other) - static_cast<base>(*this), true};
			return base::operator-(other);
		}

		template<std::size_t D>
		constexpr fixed_signed<D + bits> operator*(const fixed_signed<D>& other) const {
			if (negative && other.negative)
				return static_cast<base>(- *this) * static_cast<base>(- other);
			if (negative)
				return -((- *this) * other);
			if (other.negative)
				return -((*this) * (-other));
			return base::operator*(other);
		}

		template<std::size_t D>
		fixed_signed<D> operator%(const fixed_signed<D>& modulus) const {
			fixed_signed ret{*this};
			if (negative)
				ret = -ret;
			std::size_t msb_at = this->data_units() - 1, processed_bits = 0, start_shift = modulus.data_units() - 1;
			fixed_signed expanded_modulus{modulus};
			while (start_shift && expanded_modulus.data[start_shift] == 0)
				--start_shift;
			expanded_modulus <<= (this->data_units() - start_shift - 1) * unit_bits;
			while (ret >= modulus) {
				while (ret >= expanded_modulus)
					ret -= expanded_modulus;
				expanded_modulus >>= 1;
				if (++processed_bits % (unit_bytes * 8) == 0)
					--msb_at;
			}
			if (negative)
				ret = modulus - ret;
			return {ret};
		}

		using base::operator-;

		fixed_signed operator-() const {
			fixed_signed ret{*this};
			ret.negative = !negative;
			return ret;
		}

		template<std::size_t D>
		std::strong_ordering operator<=>(const fixed_signed<D>& other) const {
			bool this_neg = negative, other_neg = other.negative;
			if (this_neg != other_neg)		// negative values are always less than positive values and zeros
				return this_neg ? std::strong_ordering::less : std::strong_ordering::greater;

			auto&& ret = base::operator<=>(other);
			return this_neg ? 0 <=> ret : ret;
		}
	};

	template<std::size_t D>
	fixed_signed(const fixed_unsigned<D>&) -> fixed_signed<D>;

	template<std::size_t D>
	fixed_signed(const char (&hex)[D]) -> fixed_signed<(D - 1) * 4>;

	template<class V> requires std::is_integral_v<V>
	fixed_signed(V) -> fixed_signed<sizeof(V) * 8>;
}

#pragma once
#include "number/fixed.h"
#include "number/flexible.h"

namespace leaf {

	inline fixed_unsigned<128> multiply(const fixed_unsigned<128>& X, fixed_unsigned<128> Y) {
		fixed_unsigned<128> R(0xe1);
		R <<= 120;
		fixed_unsigned<128> Z;
		for (size_t i = 0; i < 128; ++i) {
			if (X.bit(127 - i))
				Z ^= Y;
			bool bit = Y.bit(0);
			Y >>= 1;
			if (bit)
				Y ^= R;
		}
		return Z;
	}

	template<std::size_t S, std::size_t D>
	void inplace_increase(fixed_unsigned<D>& val) {
		fixed_unsigned<S> val_new = val + fixed_unsigned(1);
		val.set(val_new);
	}

	template<std::size_t S, std::size_t D>
	fixed_unsigned<D> increase(fixed_unsigned<D> val) {
		fixed_unsigned<S> val_new = val + fixed_unsigned(1);
		val.set(val_new);
		return val;
	}

	inline var_unsigned increase(const std::size_t bits, var_unsigned val) {
		val.set((val + var_unsigned{1, 1}).resize(bits));
		return val;
	}

	inline void inplace_increase(const std::size_t bits, var_unsigned& val) {
		val.set((val + var_unsigned{1, 1}).resize(bits));
	}


	class gcm {
	public:
		static constexpr std::size_t block_size = 128;

		const std::size_t key_size, iv_size, tag_size;

	protected:
		var_unsigned hash_subkey_;

		/**
		 * Initialize hash subkey (per GCM spec).
		 *
		 * @note
		 * `init()` _must_ be called after `ciph` function is ready (e.g., key schedule in generated).
		 * Subclasses must call `init()` once before the use of any function.
		 */
		void init() {
			hash_subkey_ = ciph(var_unsigned(block_size));
		}

		gcm(const std::size_t key_size, const std::size_t iv_size, const std::size_t tag_size)
			: key_size(key_size), iv_size(iv_size), tag_size(tag_size) {
		}

	public:
		/**
		 * Function CIPH of GCM spec. Should at least cipher a `var_unsigned` of `block_size` bits.
		 */
		virtual var_unsigned ciph(const var_unsigned& X) const = 0;

		/**
		 * Function GCM-AE_k of GCM spec.
		 * @param iv initialization vector
		 * @param plain plain text
		 * @param data additional authentication data
		 * @return pair of ciphered text and authentication tag
		 */
		std::pair<var_unsigned, var_unsigned>
		encrypt(const var_unsigned& iv, const var_unsigned& plain, const var_unsigned& data) const {
			var_unsigned J;
			if (iv_size == 96) {
				J = iv.resize(128) << 32;
				J.set(true, 0);
			} else {
				auto J_p
					= iv.resize(128 * (1 + iv_size / 128 + (iv_size % 128 ? 0 : 1)))
						<< (iv_size % 128 ? 128 - iv_size % 128 : 0) + 64;
				J_p.set(var_unsigned{64, iv_size});
				J = ghash(J_p);
			}
			auto&& C = gctr(increase(32, J), plain);
			var_unsigned S_p(128 * (data.block_needed(128) + plain.block_needed(128) + 1));
			S_p.set(data);
			S_p <<= data.padding_needed(128) + plain.bits();
			S_p.set(C);
			S_p <<= plain.padding_needed(128) + 64;
			S_p.set(fixed_unsigned(data.bits()), 64);
			S_p <<= 64;
			S_p.set(fixed_unsigned(plain.bits()), 64);
			auto&& T = gctr(J, ghash(S_p));
			T >>= T.bits() - tag_size;
			return {std::move(C), std::move(T)};
		}

		var_unsigned decrypt(const var_unsigned& iv, const var_unsigned& cipher, const var_unsigned& data, const var_unsigned& tag) const {
			var_unsigned J(block_size);
			if (iv_size == 96) {
				J = iv.resize(block_size) << 32;
				J.set(true, 0);
			} else {
				var_unsigned J_p = iv.resize(128 * (iv_size / 128 + (iv_size % 128 ? 0 : 1) + 1));
				J_p <<= (iv_size % 128 ? 128 - iv_size % 128 : 0) + 64;
				J_p.set(var_unsigned(64, iv_size));
				J = ghash(J_p);
			}
			auto P = gctr(increase(32, J), cipher);
			var_unsigned S_p(128 * (data.block_needed(128) + cipher.block_needed(128) + 1));
			S_p.set(data);
			S_p <<= data.padding_needed(128) + cipher.bits();
			S_p.set(cipher);
			S_p <<= cipher.padding_needed(128) + 64;
			S_p.set(fixed_unsigned(data.bits()), 64);
			S_p <<= 64;
			S_p.set(fixed_unsigned(cipher.bits()), 64);
			auto&& T = gctr(J, ghash(S_p));
			T >>= T.bits() - tag_size;
			if (T != tag)
				throw std::exception();
			return P;
		}

		// function GHASH of GCM spec
		var_unsigned ghash(const var_unsigned& val) const {
			var_unsigned y(128);
			for (std::size_t i = 0; i < val.bits() / 128; ++i) {
				y ^= (val >> 128 * (val.bits() / 128 - i - 1)).resize(block_size);
				y = multiply(y, hash_subkey_);
			}
			return y;
		}

		/** function GCTR of GCM spec. */
		var_unsigned gctr(var_unsigned ICB, const var_unsigned& X) const {
			if (!X.bits())
				return {};
			var_unsigned Y(X.bits());
			const auto n = X.block_needed(block_size), excess = X.bits() % block_size ? X.bits() % block_size : block_size;
			for (size_t i = 0; i < n - 1; ++i) {
				Y <<= block_size;
				auto X_i = (X >> block_size * (n - i - 2) + excess).resize(block_size);
				Y.set(X_i ^ ciph(ICB));
				inplace_increase(32, ICB);
			}
			Y <<= excess;
			Y.set(X.resize(excess) ^ ciph(ICB) >> 128 - excess);
			return Y;
		}
	};

}

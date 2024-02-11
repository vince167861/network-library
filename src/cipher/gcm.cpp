#include "cipher/gcm.h"
#include "utils.h"
#include <stdexcept>

namespace leaf {

	const std::runtime_error decrypt_failed{"Decryption failed: authentication failed."};

	big_unsigned multiply(const big_unsigned& X, big_unsigned Y) {
		auto R = big_unsigned(0xe1);
		R.resize(128);
		R <<= 120;
		big_unsigned Z(0, 128);
		for (std::size_t i = 0; i < 128; ++i) {
			if (X.bit(127 - i))
				Z ^= Y;
			bool bit = Y.bit(0);
			Y >>= 1;
			if (bit)
				Y ^= R;
		}
		return Z;
	}

	big_unsigned increase(const std::size_t bits, big_unsigned val) {
		val.set(val + 1, bits);
		return val;
	}

	void increase(const std::size_t bits, big_unsigned& val, std::in_place_t) {
		val.set(val + 1, bits);
	}

	void gcm::init() {
		hash_subkey_ = ciph(big_unsigned(0, block_size));
	}

	big_unsigned gcm::pre_counter_(const big_unsigned& iv) const {
		if (iv_bits == 96) {
			big_unsigned J(0, block_size);
			J.set(iv);
			J <<= 32;
			J.set(true, 0);
			return J;
		}
		big_unsigned J_p(0, 128 * divide_ceiling(iv_bits, 128) + 64);
		J_p.set(iv);
		J_p <<= (iv_bits % 128 ? 128 - iv_bits % 128 : 0) + 128;
		J_p.set(big_unsigned(iv_bits), 64);
		return ghash(J_p);
	}

	big_unsigned
	gcm::tag_(const big_unsigned& ciphertext, const big_unsigned& pre_counter, const big_unsigned& auth_data) const {
		big_unsigned S_p(0, 128 * (divide_ceiling(auth_data.bits(), 128) + divide_ceiling(ciphertext.bits(), 128) + 1));
		S_p.set(auth_data);
		S_p <<= divisible_requires(auth_data.bits(), 128) + ciphertext.bits();
		S_p.set(ciphertext);
		S_p <<= divisible_requires(ciphertext.bits(), 128) + 64;
		S_p.set(big_unsigned(auth_data.bits()), 64);
		S_p <<= 64;
		S_p.set(big_unsigned(ciphertext.bits()), 64);
		auto T = gctr(pre_counter, ghash(S_p));
		T >>= T.bits() - tag_bits;
		return T;
	}

	std::pair<big_unsigned, big_unsigned>
	gcm::encrypt(const big_unsigned& iv, const big_unsigned& plain, const big_unsigned& auth_data) const {
		const auto J = pre_counter_(iv);
		const auto C = gctr(increase(32, J), plain);
		const auto T = tag_(C, J, auth_data);
		return {std::move(C), std::move(T)};
	}

	big_unsigned
	gcm::decrypt(const big_unsigned& iv, const big_unsigned& cipher, const big_unsigned& auth_data, const big_unsigned& tag) const {
		const auto J = pre_counter_(iv);
		const auto P = gctr(increase(32, J), cipher);
		const auto T = tag_(cipher, J, auth_data);
		if (T != tag)
			throw decrypt_failed;
		return P;
	}

	big_unsigned gcm::ghash(const big_unsigned& val) const {
		big_unsigned y(0, 128);
		for (std::size_t i = 0; i < val.bits() / 128; ++i) {
			y ^= val >> 128 * (val.bits() / 128 - i - 1);
			y = multiply(y, hash_subkey_);
		}
		return y;
	}

	big_unsigned gcm::gctr(big_unsigned ICB, const big_unsigned& X) const {
		if (!X.bits())
			return {};
		big_unsigned Y(0, X.bits());
		const auto n = divide_ceiling(X.bits(), block_size), excess = mod_not_exceed(X.bits(), block_size);
		for (size_t i = 0; i < n - 1; ++i) {
			const auto X_i = X >> block_size * (n - i - 2) + excess;
			Y <<= block_size;
			Y.set(X_i ^ ciph(ICB), block_size);
			increase(32, ICB, std::in_place);
		}
		Y <<= excess;
		Y.set(X ^ ciph(ICB) >> 128 - excess, excess);
		return Y;
	}
}

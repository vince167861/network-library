#include "crypto/gcm.h"
#include "internal/utils.h"
#include <stdexcept>

namespace encrypt {

	using namespace internal;

	big_unsigned gcm::multiply(const big_unsigned& X, big_unsigned Y) {
		big_unsigned R(0xe1u, 128);
		R <<= 120;
		big_unsigned Z(0u, 128);
		for (std::size_t i = 0; i < 128; ++i) {
			if (X.test(127 - i))
				Z ^= Y;
			bool bit = Y.test(0);
			Y >>= 1;
			if (bit)
				Y ^= R;
		}
		return Z;
	}

	big_unsigned increase(const std::size_t bits, big_unsigned val) {
		val.set(val + 1u, bits);
		return val;
	}

	void increase(std::in_place_t, const std::size_t bits, big_unsigned& val) {
		val.set(val + 1u, bits);
	}

	void gcm::init() {
		hash_subkey_ = ciph({0u, block_size});
	}

	big_unsigned gcm::pre_counter_(const big_unsigned& iv) const {
		if (iv_bits == 96) {
			big_unsigned J(iv, block_size);
			J <<= 32;
			J.set_bit(0, true);
			return J;
		}
		big_unsigned J_p(iv, 128 * div_ceil(iv_bits, 128) + 64);
		J_p <<= divisible_requires(iv_bits, 128) + 128;
		J_p.set(iv_bits, 64);
		return ghash(J_p);
	}

	big_unsigned
	gcm::tag_(const big_unsigned& ciphertext, const big_unsigned& pre_counter, const big_unsigned& auth_data) const {
		const auto auth_bits = auth_data.bit_most(), cipher_bits = ciphertext.bit_most();
		big_unsigned S_p(0u, 128 * (div_ceil(auth_bits, 128) + div_ceil(cipher_bits, 128) + 1));
		S_p.set(auth_data);
		S_p <<= divisible_requires(auth_bits, 128) + cipher_bits;
		S_p.set(ciphertext);
		S_p <<= divisible_requires(cipher_bits, 128) + 64;
		S_p.set(auth_bits, 64);
		S_p <<= 64;
		S_p.set(cipher_bits, 64);
		auto T = gctr(pre_counter, ghash(S_p));
		T >>= T.bit_most() - tag_bits;
		return T;
	}

	std::pair<big_unsigned, big_unsigned>
	gcm::encrypt(const big_unsigned& iv, const big_unsigned& plaintext, const big_unsigned& auth_data) const {
		const auto J = pre_counter_(iv);
		auto C = gctr(increase(32, J), plaintext);
		auto T = tag_(C, J, auth_data);
		return {std::move(C), std::move(T)};
	}

	big_unsigned
	gcm::decrypt(const big_unsigned& iv, const big_unsigned& cipher, const big_unsigned& auth_data, const big_unsigned& tag) const {
		const auto J = pre_counter_(iv);
		const auto P = gctr(increase(32, J), cipher);
		const auto T = tag_(cipher, J, auth_data);
		if (T != tag)
			throw std::runtime_error{"decryption failed: authentication failed."};
		return P;
	}

	big_unsigned gcm::ghash(const big_unsigned& X) const {
		if (X.bit_most() % 128)
			throw std::invalid_argument{"GHASH(X): X.bits must be multiple of 128"};
		big_unsigned Y(0u, 128);
		const auto src_units = X.bit_most() / 128;
		for (std::size_t i = 0; i < src_units; ++i) {
			Y ^= {X.substr(16 * (src_units - i - 1), 16)};
			Y = multiply(Y, hash_subkey_);
		}
		return Y;
	}

	big_unsigned gcm::gctr(big_unsigned ICB, const big_unsigned& X) const {
		if (!X.bit_most())
			return {};
		big_unsigned Y(0u, X.bit_most());
		const auto n = div_ceil(X.bit_most(), block_size), excess = mod_not_exceed(X.bit_most(), block_size);
		for (size_t i = 0; i < n - 1; ++i) {
			Y <<= block_size;
			Y.set(X >> block_size * (n - i - 2) + excess ^ ciph(ICB), block_size);
			increase(std::in_place, 32, ICB);
		}
		Y <<= excess;
		Y.set(X ^ ciph(ICB) >> 128 - excess, excess);
		return Y;
	}
}

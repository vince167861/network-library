#include "cipher/gcm.h"
#include <stdexcept>

namespace leaf {

	const std::runtime_error decrypt_failed{"Decryption failed: authentication failed."};

	var_unsigned multiply(const var_unsigned& X, var_unsigned Y) {
		auto R = var_unsigned::from_hex("e1").resize(128);
		R <<= 120;
		var_unsigned Z(128);
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

	var_unsigned increase(const std::size_t bits, var_unsigned val) {
		val.set((val + var_unsigned{1, 1}).resize(bits));
		return val;
	}

	void inplace_increase(const std::size_t bits, var_unsigned& val) {
		val.set((val + var_unsigned{1, 1}).resize(bits));
	}

	void gcm::init() {
		hash_subkey_ = ciph(var_unsigned(block_size));
	}

	std::pair<var_unsigned, var_unsigned>
	gcm::encrypt(const var_unsigned& iv, const var_unsigned& plain, const var_unsigned& data) const {
		var_unsigned J;
		if (iv_size == 96) {
			J = iv.resize(128) << 32;
			J.set(true, 0);
		} else {
			auto J_p
					= iv.resize(128 * (1 + iv_size / 128 + (iv_size % 128 ? 0 : 1)))
							<< (iv_size % 128 ? 128 - iv_size % 128 : 0) + 64;
			J_p.set(var_unsigned::from_number(iv_size), 64);
			J = ghash(J_p);
		}
		auto&& C = gctr(increase(32, J), plain);
		var_unsigned S_p(128 * (data.block_needed(128) + plain.block_needed(128) + 1));
		S_p.set(data);
		S_p <<= data.padding_needed(128) + plain.bits();
		S_p.set(C);
		S_p <<= plain.padding_needed(128) + 64;
		S_p.set(var_unsigned::from_number(data.bits()), 64);
		S_p <<= 64;
		S_p.set(var_unsigned::from_number(plain.bits()), 64);
		auto T = gctr(J, ghash(S_p));
		T >>= T.bits() - tag_size;
		return {std::move(C), std::move(T)};
	}

	var_unsigned
	gcm::decrypt(const var_unsigned& iv, const var_unsigned& cipher, const var_unsigned& data, const var_unsigned& tag) const {
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
		S_p.set(var_unsigned::from_number(data.bits()), 64);
		S_p <<= 64;
		S_p.set(var_unsigned::from_number(cipher.bits()), 64);
		auto&& T = gctr(J, ghash(S_p));
		T >>= T.bits() - tag_size;
		if (T != tag)
			throw decrypt_failed;
		return P;
	}

	var_unsigned gcm::ghash(const var_unsigned& val) const {
		var_unsigned y(128);
		for (std::size_t i = 0; i < val.bits() / 128; ++i) {
			y ^= (val >> 128 * (val.bits() / 128 - i - 1)).resize(block_size);
			y = multiply(y, hash_subkey_);
		}
		return y;
	}

	var_unsigned gcm::gctr(var_unsigned ICB, const var_unsigned& X) const {
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
}
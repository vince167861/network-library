#include "tls-cipher/cipher_suite_gcm.h"

namespace leaf::network::tls {

	cipher_suite_gcm::cipher_suite_gcm(std::size_t key_bytes, std::size_t iv_bytes, std::size_t tag_bytes)
			: tag_bits_(tag_bytes * 8), gcm(key_bytes * 8, iv_bytes * 8, tag_bytes * 8) {
	}

	big_unsigned cipher_suite_gcm::encrypt(big_unsigned nonce, big_unsigned auth, big_unsigned plaintext) const {
		nonce.resize(iv_bits);
		auto [ciphered, tag] = gcm::encrypt(nonce, plaintext, auth);
		ciphered.resize(ciphered.bit_most() + tag.bit_most());
		ciphered <<= tag.bit_most();
		ciphered.set(tag);
		return ciphered;
	}

	big_unsigned
	cipher_suite_gcm::decrypt(const big_unsigned nonce, const big_unsigned auth, const big_unsigned ciphertext) const {
		const big_unsigned __enc(ciphertext >> tag_bits_, ciphertext.bit_most() - tag_bits_), tag(ciphertext, tag_bits_);
		return gcm::decrypt(nonce, __enc, auth, tag);
	}
}

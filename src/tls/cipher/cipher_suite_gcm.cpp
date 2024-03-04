#include "tls/cipher/cipher_suite_gcm.h"

namespace network::tls {

	cipher_suite_gcm::cipher_suite_gcm(const std::size_t __k, const std::size_t __iv, const std::size_t __t)
			: gcm(__k * 8, __iv * 8, __t * 8), tag_bits_(__t * 8) {
	}

	big_unsigned cipher_suite_gcm::encrypt(big_unsigned nonce, const big_unsigned auth, const big_unsigned plaintext) const {
		nonce.resize(iv_bits);
		auto [ciphered, tag] = gcm::encrypt(nonce, plaintext, auth);
		ciphered.resize(ciphered.bit_most() + tag.bit_most());
		ciphered <<= tag.bit_most();
		ciphered.set(tag);
		return ciphered;
	}

	big_unsigned
	cipher_suite_gcm::decrypt(const big_unsigned nonce, const big_unsigned auth, const big_unsigned ciphertext) const {
		return gcm::decrypt(
			nonce,
			{ciphertext >> tag_bits_, ciphertext.bit_most() - tag_bits_},
			auth,
			{ciphertext, tag_bits_});
	}
}

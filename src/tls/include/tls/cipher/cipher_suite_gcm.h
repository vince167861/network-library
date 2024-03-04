#pragma once
#include "cipher_suite.h"
#include "crypto/gcm.h"

namespace network::tls {

	class cipher_suite_gcm: public encrypt::gcm, virtual public cipher_suite {

		const std::size_t tag_bits_;

	protected:
		cipher_suite_gcm(std::size_t key_bytes, std::size_t iv_bytes, std::size_t tag_bytes);

	public:
		[[nodiscard]]
		big_unsigned encrypt(big_unsigned nonce, big_unsigned auth, big_unsigned plaintext) const override;

		big_unsigned decrypt(big_unsigned nonce, big_unsigned auth, big_unsigned ciphertext) const override;
	};
}

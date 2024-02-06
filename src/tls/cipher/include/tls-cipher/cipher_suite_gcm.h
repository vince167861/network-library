#pragma once

#include "cipher_suite.h"
#include "cipher/gcm.h"


namespace leaf::network::tls {


	class cipher_suite_gcm: public gcm, virtual public cipher_suite {
	protected:
		cipher_suite_gcm(std::size_t key_bytes, std::size_t iv_bytes, std::size_t tag_bytes);

	public:
		[[nodiscard]] std::string
		encrypt(std::string_view nonce, std::string_view auth, std::string_view plain_text) const override;

		std::string
		decrypt(std::string_view nonce, std::string_view data, std::string_view cipher_text) const override;
	};
}

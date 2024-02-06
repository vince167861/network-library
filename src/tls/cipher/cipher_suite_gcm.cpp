#include "tls-cipher/cipher_suite_gcm.h"

namespace leaf::network::tls {

	cipher_suite_gcm::cipher_suite_gcm(std::size_t key_bytes, std::size_t iv_bytes, std::size_t tag_bytes)
		: gcm(key_bytes * 8, iv_bytes * 8, tag_bytes * 8) {
	}

	std::string cipher_suite_gcm::encrypt(const std::string_view nonce, const std::string_view auth, const std::string_view plain_text) const {
		auto nonce_data = var_unsigned::from_bytes(nonce).resize(iv_size);
		auto plain_data = var_unsigned::from_bytes(plain_text);
		auto auth_data = var_unsigned::from_bytes(auth);
		auto [ciphered, tag] = gcm::encrypt(nonce_data, plain_data, auth_data);
		return ciphered.to_bytestring(std::endian::big) + tag.to_bytestring(std::endian::big);
	}

	std::string cipher_suite_gcm::decrypt(std::string_view nonce, std::string_view data, std::string_view cipher_text) const {
		auto nonce_data = var_unsigned::from_bytes(nonce).resize(iv_size);
		auto cipher_data = var_unsigned::from_bytes({cipher_text.begin(), cipher_text.end() - 16});
		auto auth_data = var_unsigned::from_bytes(data);
		auto tag_data = var_unsigned::from_bytes({cipher_text.end() - 16, cipher_text.end()});
		return gcm::decrypt(nonce_data, cipher_data, auth_data, tag_data).to_bytestring(std::endian::big);
	}
}

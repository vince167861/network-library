#include "tls-cipher/gcm_cipher.h"

#include "tls-record/alert.h"


namespace leaf::network::tls {

	gcm_cipher::gcm_cipher(std::size_t key_bytes, std::size_t iv_bytes, std::size_t tag_bytes)
		: gcm(key_bytes * 8, iv_bytes * 8, tag_bytes * 8) {
	}

	std::string gcm_cipher::encrypt(const std::string_view nonce, const std::string_view auth, const std::string_view plain_text) const {
		auto nonce_data = var_unsigned::from_bytes(nonce).resize(iv_size);
		auto plain_data = var_unsigned::from_bytes(plain_text);
		auto auth_data = var_unsigned::from_bytes(auth);
		auto [ciphered, tag] = gcm::encrypt(nonce_data, plain_data, auth_data);
		return ciphered.to_bytes() + tag.to_bytes();
	}

	std::string gcm_cipher::decrypt(std::string_view nonce, std::string_view data, std::string_view cipher_text) const {
		auto nonce_data = var_unsigned::from_bytes(nonce).resize(iv_size);
		auto cipher_data = var_unsigned::from_bytes({cipher_text.begin(), cipher_text.end() - 16});
		auto auth_data = var_unsigned::from_bytes(data);
		auto tag_data = var_unsigned::from_bytes({cipher_text.end() - 16, cipher_text.end()});
		try {
			return gcm::decrypt(nonce_data, cipher_data, auth_data, tag_data).to_bytes();
		} catch (const std::exception&) {
			throw alert::bad_record_mac();
		}
	}
}

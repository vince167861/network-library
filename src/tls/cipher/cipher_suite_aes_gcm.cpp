#include "tls-cipher/cipher_suite_aes_gcm.h"
#include "tls-cipher/cipher_suite.h"
#include "hash/sha2.h"
#include "hash/hmac.h"

namespace leaf::network::tls {

	aes_128_gcm::aes_128_gcm()
			: cipher_suite_gcm(16, 12, 16) {
	}

	var_unsigned aes_128_gcm::ciph(const var_unsigned& X) const {
		auto X_copied = X;
		aes_128.cipher(X_copied, key_schedule);
		return X_copied;
	}

	void aes_128_gcm::set_key(const number_base& secret_key) {
		var_unsigned secret_key_(secret_key);
		aes_128.key_expansion(secret_key_, key_schedule);
		init();
	}

	std::string aes_128_gcm_sha256::hash(const std::string_view hash) const {
		return sha_256::hash(var_unsigned::from_bytes(hash)).to_bytestring(std::endian::big);
	}

	std::string aes_128_gcm_sha256::HMAC_hash(const std::string_view data, const std::string_view key) const {
		return hashing::HMAC_sha_256(var_unsigned::from_bytes(data), var_unsigned::from_bytes(key))
				.to_bytestring(std::endian::big);
	}

	aes_128_gcm_sha256::aes_128_gcm_sha256()
			: cipher_suite(cipher_suite_t::AES_128_GCM_SHA256, 32, 16, 12) {
	}

	aes_256_gcm::aes_256_gcm()
			: cipher_suite_gcm(32, 12, 16) {
	}

	var_unsigned aes_256_gcm::ciph(const var_unsigned& X) const {
		auto X_copied = X;
		aes_256.cipher(X_copied, key_schedule);
		return X_copied;
	}

	void aes_256_gcm::set_key(const number_base& secret_key) {
		var_unsigned secret_key_(secret_key);
		aes_256.key_expansion(secret_key_, key_schedule);
		init();
	}

	std::string aes_256_gcm_sha384::hash(std::string_view hash) const {
		return sha_384::hash(var_unsigned::from_bytes(hash)).to_bytestring(std::endian::big);
	}

	std::string aes_256_gcm_sha384::HMAC_hash(std::string_view data, std::string_view key) const {
		return hashing::HMAC_sha_384(var_unsigned::from_bytes(data), var_unsigned::from_bytes(key))
				.to_bytestring(std::endian::big);
	}

	aes_256_gcm_sha384::aes_256_gcm_sha384()
			: cipher_suite(cipher_suite_t::AES_256_GCM_SHA384, 48, 32, 12) {
	}
}

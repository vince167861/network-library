#include "tls-cipher/aes_gcm.h"
#include "tls-cipher/cipher_suite.h"
#include "hash/sha2.h"
#include "hash/hmac.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {
	std::string aes_128_gcm_sha256::hash(const std::string_view hash) const {
		return sha_256::hash(var_unsigned::from_bytes(hash)).to_bytes();
	}

	std::string aes_128_gcm_sha256::HMAC_hash(const std::string_view data, const std::string_view key) const {
		return hashing::HMAC_sha_256(var_unsigned::from_bytes(data), var_unsigned::from_bytes(key)).to_bytes();
	}

	aes_128_gcm_sha256::aes_128_gcm_sha256()
		: cipher_suite(cipher_suite_t::AES_128_GCM_SHA256, 32,16, 12) {
	}

	void aes_128_gcm::print(std::ostream& s) const {
		s << "aes_128_gcm{}";
	}

	aes_128_gcm::aes_128_gcm()
			: gcm_cipher(16, 12, 16) {
	}

	void aes_256_gcm::print(std::ostream& s) const {
		s << "aes_256_gcm{}";
	}

	aes_256_gcm::aes_256_gcm()
		: gcm_cipher(32, 12, 16) {
	}

	std::string aes_256_gcm_sha384::hash(std::string_view hash) const {
		return sha_384::hash(var_unsigned::from_bytes(hash)).to_bytes();
	}

	std::string aes_256_gcm_sha384::HMAC_hash(std::string_view data, std::string_view key) const {
		return hashing::HMAC_sha_384(var_unsigned::from_bytes(data), var_unsigned::from_bytes(key)).to_bytes();
	}

	aes_256_gcm_sha384::aes_256_gcm_sha384()
		: cipher_suite(cipher_suite_t::AES_256_GCM_SHA384, 48, 32, 12) {
	}
}

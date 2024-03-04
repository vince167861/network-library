#include "tls/cipher/cipher_suite_aes_gcm.h"
#include "crypto/aes.h"
#include "crypto/hmac.h"
#include "crypto/sha2.h"
#include "tls/util/type.h"

namespace network::tls {

	aes_128_gcm::aes_128_gcm()
			: cipher_suite_gcm(16, 12, 16) {
	}

	void aes_128_gcm::set_key(const big_unsigned& __k) {
		encrypt::aes_128.key_expansion(__k, key_schedule);
		init();
	}

	big_unsigned aes_128_gcm::ciph(const big_unsigned& X) const {
		auto X_copied = X;
		encrypt::aes_128.cipher(X_copied, key_schedule);
		return X_copied;
	}

	byte_string aes_128_gcm_sha256::hash(const byte_string_view __s) const {
		return sha_256::hash({__s, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}

	byte_string aes_128_gcm_sha256::HMAC_hash(const byte_string_view data, const byte_string_view key) const {
		return hashing::HMAC_SHA_256(data, key);
	}

	aes_128_gcm_sha256::aes_128_gcm_sha256()
			: cipher_suite(cipher_suite_t::AES_128_GCM_SHA256, 32, 16, 12) {
	}

	aes_256_gcm::aes_256_gcm()
			: cipher_suite_gcm(32, 12, 16) {
	}

	big_unsigned aes_256_gcm::ciph(const big_unsigned& X) const {
		auto X_copied = X;
		encrypt::aes_256.cipher(X_copied, key_schedule);
		return X_copied;
	}

	void aes_256_gcm::set_key(const big_unsigned& __k) {
		encrypt::aes_256.key_expansion(__k, key_schedule);
		init();
	}

	byte_string aes_256_gcm_sha384::hash(const byte_string_view hash) const {
		return sha_384::hash({hash, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}

	byte_string aes_256_gcm_sha384::HMAC_hash(const byte_string_view data, const byte_string_view key) const {
		return hashing::HMAC_sha_384(data, key);
	}

	aes_256_gcm_sha384::aes_256_gcm_sha384()
			: cipher_suite(cipher_suite_t::AES_256_GCM_SHA384, 48, 32, 12) {
	}
}

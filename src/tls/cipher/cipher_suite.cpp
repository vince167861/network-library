#include "tls/cipher/cipher_suite.h"
#include "tls/cipher/cipher_suite_aes_gcm.h"
#include "internal/utils.h"

namespace network::tls {

	cipher_suite::cipher_suite(const cipher_suite_t cs, std::size_t digest_length, std::size_t key_length, std::size_t iv_length)
			: value(cs), digest_length(digest_length), key_length(key_length), iv_length(iv_length) {
	}

	std::unique_ptr<cipher_suite> get_cipher_suite(cipher_suite_t suite) {
		switch (suite) {
			case cipher_suite_t::AES_128_GCM_SHA256:
				return std::make_unique<aes_128_gcm_sha256>();
			case cipher_suite_t::AES_256_GCM_SHA384:
				return std::make_unique<aes_256_gcm_sha384>();
			default:
				return std::make_unique<unimplemented_cipher_suite>(suite);
		}
	}

	byte_string
	cipher_suite::HKDF_expand_label(const byte_string_view key, const byte_string_view label, const byte_string_view context, const std::uint16_t length) const {
		return HKDF_expand(key, HKDF_info(label, context, length), length);
	}

	byte_string cipher_suite::HKDF_info(const byte_string_view label, const byte_string_view context, const std::uint16_t length) {
		using internal::write;
		byte_string info;
		const std::uint8_t label_length = 6 + label.size(), context_length = context.size();
		info.reserve(sizeof length + sizeof label_length + label_length + sizeof context_length + context_length);
		write(std::endian::big, info, length);
		write(std::endian::big, info, label_length);
		info += reinterpret_cast<const std::uint8_t*>("tls13 ");
		info += label;
		write(std::endian::big, info, context_length);
		info += context;
		return info;
	}

	byte_string cipher_suite::HKDF_expand(const byte_string_view key, const byte_string_view info, std::size_t length) const {
		byte_string ret;
		ret.reserve(length + digest_length);
		byte_string T;
		uint8_t i = 1;
		while (ret.size() < length) {
			byte_string msg;
			msg += T;
			msg += info;
			msg.push_back(i++);
			T = HMAC_hash(msg, key);
			ret += T;
		}
		ret.resize(length);
		return ret;
	}

	byte_string cipher_suite::derive_secret(const byte_string_view key, const byte_string_view label, const byte_string_view msg) const {
		return HKDF_expand_label(key, label, hash(msg), digest_length);
	}
}

#include "tls-cipher/cipher_suite.h"

#include "tls-cipher/aes_gcm.h"
#include "utils.h"

namespace leaf::network::tls {

	cipher_suite::cipher_suite(cipher_suite_t cs, std::size_t digest_length, std::size_t key_length, std::size_t iv_length)
			: value(cs), digest_length(digest_length), key_length(key_length), iv_length(iv_length) {
	}

	cipher_suite* get_cipher_suite(const std::string_view name) {
		if (name == "AES_128_GCM_SHA256")
			return new aes_128_gcm_sha256;
		if (name == "AES_256_GCM_SHA384")
			return new aes_256_gcm_sha384;
		return nullptr;
	}

	std::ostream& operator<<(std::ostream& s, const cipher_suite& c) {
		c.print(s);
		return s;
	}

	std::string cipher_suite::HKDF_expand_label(std::string_view key, std::string_view label, std::string_view context, uint16_t length) const {
		return HKDF_expand(key, HKDF_info(label, context, length), length);
	}

	std::string cipher_suite::HKDF_info(std::string_view label, std::string_view context, uint16_t length) {
		std::string info;
		uint8_t label_length = 6 + label.size();
		uint8_t context_length = context.size();
		info.reserve(sizeof length + sizeof label_length + label_length + sizeof context_length + context_length);
		reverse_write(info, length);
		reverse_write(info, label_length);
		info += "tls13 ";
		info += label;
		reverse_write(info, context_length);
		info += context;
		return info;
	}

	std::string cipher_suite::HKDF_expand(std::string_view key, std::string_view info, std::size_t length) const {
		[[maybe_unused]] auto N = length / digest_length + (length % digest_length ? 1 : 0);
		std::string ret;
		ret.reserve(length + digest_length);
		std::string T;
		uint8_t i = 1;
		while (ret.size() < length) {
			std::string msg;
			msg += T;
			msg += info;
			msg.push_back(i++);
			T = HMAC_hash(msg, key);
			ret += T;
		}
		ret.resize(length);
		return ret;
	}

	std::string cipher_suite::derive_secret(std::string_view key, std::string_view label, std::string_view msg) const {
		return HKDF_expand_label(key, label, hash(msg), digest_length);
	}
}

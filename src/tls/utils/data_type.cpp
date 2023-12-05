#include "tls-utils/type.h"

#include "macro.h"

#include <iomanip>

namespace leaf {
	std::ostream& operator<<(std::ostream& s, protocol_version_t version) {
		switch (version) {
			build_enum_item(s, protocol_version_t, TLS1_3)
			build_enum_item(s, protocol_version_t, TLS1_2)
			build_enum_item(s, protocol_version_t, TLS1_0)
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(4) << std::setfill('0') << static_cast<uint16_t>(version) << ")";
		return s;
	}

	std::ostream& operator<<(std::ostream& s, named_group_t group) {
		switch (group) {
			build_enum_item(s, named_group_t, secp256r1)
			build_enum_item(s, named_group_t, secp384r1)
			build_enum_item(s, named_group_t, secp521r1)
			build_enum_item(s, named_group_t, x25519)
			build_enum_item(s, named_group_t, x448)
			build_enum_item(s, named_group_t, ffdhe2048)
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(4) << std::setfill('0') << static_cast<uint16_t>(group) << ")";
		return s;
	}

	std::ostream& operator<<(std::ostream& s, cipher_suite_t suite) {
		switch (suite) {
			build_enum_item(s, cipher_suite_t, AES_128_GCM_SHA256)
			build_enum_item(s, cipher_suite_t, AES_256_GCM_SHA384)
			build_enum_item(s, cipher_suite_t, CHACHA20_POLY1305_SHA256)
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(4) << std::setfill('0') << static_cast<uint16_t>(suite) << ")";
		return s;
	}

	std::ostream& operator<<(std::ostream& s, signature_scheme_t scheme) {
		switch (scheme) {
			build_enum_item(s, signature_scheme_t, rsa_pkcs1_sha256)
			build_enum_item(s, signature_scheme_t, rsa_pkcs1_sha384)
			build_enum_item(s, signature_scheme_t, rsa_pkcs1_sha512)
			build_enum_item(s, signature_scheme_t, rsa_pss_rsae_sha256)
			build_enum_item(s, signature_scheme_t, rsa_pss_rsae_sha384)
			build_enum_item(s, signature_scheme_t, rsa_pss_rsae_sha512)
			build_enum_item(s, signature_scheme_t, ecdsa_secp256r1_sha256)
			build_enum_item(s, signature_scheme_t, ecdsa_secp384r1_sha384)
			build_enum_item(s, signature_scheme_t, ecdsa_secp521r1_sha512)
			build_enum_item(s, signature_scheme_t, ed25519)
			build_enum_item(s, signature_scheme_t, ed448)
			build_enum_item_extra(s, signature_scheme_t, ecdsa_sha1, " [deprecated]")
			build_enum_item_extra(s, signature_scheme_t, rsa_pkcs1_sha1, " [deprecated]")
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(4) << std::setfill('0') << static_cast<uint16_t>(scheme) << ")";
		return s;
	}

	std::ostream& operator<<(std::ostream& s, alert_level_t lvl) {
		switch (lvl) {
			build_enum_item(s, alert_level_t, fatal)
			build_enum_item(s, alert_level_t, warning)
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(1) << std::setfill('0') << (static_cast<uint16_t>(lvl) & 0xff) << ")";
		return s;
	}

	std::ostream& operator<<(std::ostream& s, alert_description_t item) {
		switch (item) {
			build_enum_item(s, alert_description_t, close_notify)
			build_enum_item(s, alert_description_t, unexpected_message)
			build_enum_item(s, alert_description_t, bad_record_mac)
			build_enum_item(s, alert_description_t, record_overflow)
			build_enum_item(s, alert_description_t, handshake_failure)
			build_enum_item(s, alert_description_t, illegal_parameter)
			build_enum_item(s, alert_description_t, decode_error)
			build_enum_item(s, alert_description_t, decrypt_error)
			default:
				s << "unknown";
		}
		s << " (0x" << std::hex << std::setw(1) << std::setfill('0') << (static_cast<uint16_t>(item) & 0xff) << ")";
		return s;
	}
}

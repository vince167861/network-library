#pragma once

#include <ostream>
#include <cstdint>

namespace leaf {
	using extension_size_t = uint16_t;
	using ext_data_size_t = uint16_t;
	using random_t = uint8_t[32];

	enum class protocol_version_t: uint16_t {
		SSL3_0 = 0x0300, TLS1_0 = 0x0301, TLS1_1 = 0x0302, TLS1_2 = 0x0303, TLS1_3 = 0x0304
	};

	std::ostream& operator<<(std::ostream&, protocol_version_t);

	enum class named_group_t: uint16_t {
		secp256r1 = 0x0017, secp384r1 = 0x0018, secp521r1 = 0x0019, x25519 = 0x001d, x448 = 0x001e,
		ffdhe2048 = 0x0100, ffdhe3072 = 0x0101, ffdhe4096 = 0x0102, ffdhe6614 = 0x0103, ffdhe8192 = 0x0104,
	};

	std::ostream& operator<<(std::ostream& s, named_group_t);

	enum class cipher_suite_t: uint16_t {
		AES_128_GCM_SHA256 = 0x1301, AES_256_GCM_SHA384 = 0x1302, CHACHA20_POLY1305_SHA256 = 0x1303
	};

	std::ostream& operator<<(std::ostream& s, cipher_suite_t);

	enum class signature_scheme_t: uint16_t {
		rsa_pkcs1_sha256 = 0x0401, rsa_pkcs1_sha384 = 0x0501, rsa_pkcs1_sha512 = 0x0601,
		ecdsa_secp256r1_sha256 = 0x0403, ecdsa_secp384r1_sha384 = 0x0503, ecdsa_secp521r1_sha512 = 0x0603,
		rsa_pss_rsae_sha256 = 0x0804, rsa_pss_rsae_sha384 = 0x0805, rsa_pss_rsae_sha512 = 0x0806,
		ed25519 = 0x0807, ed448 = 0x0808, rsa_pss_pss_sha256 = 0x0809, rsa_pss_pss_sha384 = 0x080a,
		rsa_pss_pss_sha512 = 0x080b, rsa_pkcs1_sha1 [[deprecated]] = 0x0201, ecdsa_sha1 [[deprecated]] = 0x0203
	};

	std::ostream& operator<<(std::ostream& s, signature_scheme_t);

	enum class alert_level_t: uint8_t {
		warning = 1, fatal = 2
	};

	std::ostream& operator<<(std::ostream&, alert_level_t);

	enum class alert_description_t: uint8_t {
		close_notify = 0, unexpected_message = 10, bad_record_mac = 20, record_overflow = 22,
		handshake_failure = 40, bad_certificate = 42, unsupported_certificate = 43,
		certificate_revoked = 44, certificate_expired = 45, certificate_unknown = 46,
		illegal_parameter = 47, unknown_ca = 48, access_denied = 49, decode_error = 50,
		decrypt_error = 51, protocol_version = 70, insufficient_security = 71, internal_error = 80,
		inappropriate_fallback = 86, user_canceled = 90, missing_extension = 109, unsupported_extension = 110,
		unrecognized_name = 112, bad_certificate_status_response = 113, unknown_psk_identity = 115,
		certificate_required = 116, no_application_protocol = 120,
	};

	std::ostream& operator<<(std::ostream&, alert_description_t);
}

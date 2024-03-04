#include "tls/util/type.h"
#include "internal/macro.h"

using namespace network::tls;

std::format_context::iterator
std::formatter<content_type_t>::format(content_type_t type, std::format_context& ctx) const {
	using network::tls::content_type_t;
	auto it = ctx.out();
	switch (type) {
		build_enum_item2(it, content_type_t, change_cipher_spec)
		build_enum_item2(it, content_type_t, alert)
		build_enum_item2(it, content_type_t, handshake)
		build_enum_item2(it, content_type_t, application_data)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<content_type_t>>(type));
}

std::format_context::iterator
std::formatter<ext_type_t>::format(ext_type_t type, std::format_context& ctx) const {
	using network::tls::ext_type_t;
	auto it = ctx.out();
	switch (type) {
		build_enum_item2(it, ext_type_t, server_name)
		build_enum_item2(it, ext_type_t, max_fragment_length)
		build_enum_item2(it, ext_type_t, status_request)
		build_enum_item2(it, ext_type_t, supported_versions)
		build_enum_item2(it, ext_type_t, key_share)
		build_enum_item2(it, ext_type_t, alpn)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<ext_type_t>>(type));
}

std::format_context::iterator
std::formatter<protocol_version_t>::format(protocol_version_t pv, std::format_context& ctx) const {
	using network::tls::protocol_version_t;
	auto it = ctx.out();
	switch (pv) {
		build_enum_item2(it, protocol_version_t, TLS1_3)
		build_enum_item2(it, protocol_version_t, TLS1_2)
		build_enum_item2(it, protocol_version_t, TLS1_0)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<protocol_version_t>>(pv));
}

std::format_context::iterator
std::formatter<named_group_t>::format(named_group_t ndgp, std::format_context& ctx) const {
	auto it = ctx.out();
	switch (ndgp) {
		build_enum_item2(it, named_group_t, secp256r1)
		build_enum_item2(it, named_group_t, secp384r1)
		build_enum_item2(it, named_group_t, secp521r1)
		build_enum_item2(it, named_group_t, x25519)
		build_enum_item2(it, named_group_t, x448)
		build_enum_item2(it, named_group_t, ffdhe2048)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<named_group_t>>(ndgp));
}

std::format_context::iterator
std::formatter<cipher_suite_t>::format(cipher_suite_t st, std::format_context& ctx) const {
	auto it = ctx.out();
	switch (st) {
		build_enum_item2(it, cipher_suite_t, AES_128_GCM_SHA256)
		build_enum_item2(it, cipher_suite_t, AES_256_GCM_SHA384)
		build_enum_item2(it, cipher_suite_t, CHACHA20_POLY1305_SHA256)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<cipher_suite_t>>(st));
}

std::format_context::iterator
std::formatter<signature_scheme_t>::format(signature_scheme_t schm, std::format_context& ctx) const {
	auto it = ctx.out();
	switch (schm) {
		build_enum_item2(it, signature_scheme_t, rsa_pkcs1_sha256)
		build_enum_item2(it, signature_scheme_t, rsa_pkcs1_sha384)
		build_enum_item2(it, signature_scheme_t, rsa_pkcs1_sha512)
		build_enum_item2(it, signature_scheme_t, rsa_pss_rsae_sha256)
		build_enum_item2(it, signature_scheme_t, rsa_pss_rsae_sha384)
		build_enum_item2(it, signature_scheme_t, rsa_pss_rsae_sha512)
		build_enum_item2(it, signature_scheme_t, ecdsa_secp256r1_sha256)
		build_enum_item2(it, signature_scheme_t, ecdsa_secp384r1_sha384)
		build_enum_item2(it, signature_scheme_t, ecdsa_secp521r1_sha512)
		build_enum_item2(it, signature_scheme_t, ed25519)
		build_enum_item2(it, signature_scheme_t, ed448)
		build_enum_item_extra2(it, signature_scheme_t, ecdsa_sha1, " [deprecated]")
		build_enum_item_extra2(it, signature_scheme_t, rsa_pkcs1_sha1, " [deprecated]")
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<signature_scheme_t>>(schm));
}

std::format_context::iterator
std::formatter<alert_level_t>::format(alert_level_t level, std::format_context& ctx) const {
	auto it = ctx.out();
	switch (level) {
		build_enum_item2(it, alert_level_t, fatal)
		build_enum_item2(it, alert_level_t, warning)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<alert_level_t>>(level));
}

std::format_context::iterator
std::formatter<alert_description_t>::format(alert_description_t dsc, std::format_context& ctx) const {
	auto s = ctx.out();
	switch (dsc) {
		build_enum_item2(s, alert_description_t, close_notify)
		build_enum_item2(s, alert_description_t, unexpected_message)
		build_enum_item2(s, alert_description_t, bad_record_mac)
		build_enum_item2(s, alert_description_t, record_overflow)
		build_enum_item2(s, alert_description_t, handshake_failure)
		build_enum_item2(s, alert_description_t, illegal_parameter)
		build_enum_item2(s, alert_description_t, decode_error)
		build_enum_item2(s, alert_description_t, decrypt_error)
		default:
			s = std::ranges::copy("unknown"sv, s).out;
	}
	return std::format_to(s, "({:#x})", static_cast<std::underlying_type_t<alert_description_t>>(dsc));
}

std::format_context::iterator
std::formatter<psk_key_exchange_mode_t>::format(psk_key_exchange_mode_t mode, std::format_context& ctx) const {
	auto s = ctx.out();
	switch (mode) {
		build_enum_item2(s, psk_key_exchange_mode_t, psk_dhe_ke)
		build_enum_item2(s, psk_key_exchange_mode_t, psk_ke)
		default:
			s = std::ranges::copy("unknown"sv, s).out;
	}
	return std::format_to(s, "({:#x})", static_cast<std::underlying_type_t<psk_key_exchange_mode_t>>(mode));
}

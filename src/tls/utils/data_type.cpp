#include "tls-utils/type.h"

#include "macro.h"

std::format_context::iterator
std::formatter<leaf::content_type_t>::format(leaf::content_type_t type, std::format_context& ctx) const {
	using leaf::content_type_t;
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
std::formatter<leaf::ext_type_t>::format(leaf::ext_type_t type, std::format_context& ctx) const {
	using leaf::ext_type_t;
	auto it = ctx.out();
	switch (type) {
		build_enum_item2(it, ext_type_t, server_name)
		build_enum_item2(it, ext_type_t, max_fragment_length)
		build_enum_item2(it, ext_type_t, status_request)
		build_enum_item2(it, ext_type_t, supported_versions)
		build_enum_item2(it, ext_type_t, key_share)
		default:
			it = std::ranges::copy("unknown"sv, it).out;
	}
	return std::format_to(it, "({:#x})", static_cast<std::underlying_type_t<ext_type_t>>(type));
}

std::format_context::iterator
std::formatter<leaf::protocol_version_t>::format(leaf::protocol_version_t pv, std::format_context& ctx) const {
	using leaf::protocol_version_t;
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
std::formatter<leaf::named_group_t>::format(leaf::named_group_t ndgp, std::format_context& ctx) const {
	using leaf::named_group_t;
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
std::formatter<leaf::cipher_suite_t>::format(leaf::cipher_suite_t st, std::format_context& ctx) const {
	using leaf::cipher_suite_t;
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
std::formatter<leaf::signature_scheme_t>::format(leaf::signature_scheme_t schm, std::format_context& ctx) const {
	using leaf::signature_scheme_t;
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
std::formatter<leaf::alert_level_t>::format(leaf::alert_level_t level, std::format_context& ctx) const {
	using leaf::alert_level_t;
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
std::formatter<leaf::alert_description_t>::format(leaf::alert_description_t dsc, std::format_context& ctx) const {
	using leaf::alert_description_t;
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
std::formatter<leaf::psk_key_exchange_mode_t>::format(leaf::psk_key_exchange_mode_t mode, std::format_context& ctx) const {
	using leaf::psk_key_exchange_mode_t;
	auto s = ctx.out();
	switch (mode) {
		build_enum_item2(s, psk_key_exchange_mode_t, psk_dhe_ke)
		build_enum_item2(s, psk_key_exchange_mode_t, psk_ke)
		default:
			s = std::ranges::copy("unknown"sv, s).out;
	}
	return std::format_to(s, "({:#x})", static_cast<std::underlying_type_t<psk_key_exchange_mode_t>>(mode));
}

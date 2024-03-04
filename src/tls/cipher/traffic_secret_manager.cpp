#include "tls/cipher/traffic_secret_manager.h"

namespace network::tls {

	traffic_secret_manager::traffic_secret_manager(const endpoint_type type, std::unique_ptr<cipher_suite>& active)
			: endpoint_type_(type), active_cipher_(active) {
	}

	byte_string traffic_secret_manager::encrypt(const byte_string_view header, const byte_string_view fragment) {
		big_unsigned record_nonce(write_nonce++, active_cipher_->iv_length * 8);
		switch (endpoint_type_) {
			case endpoint_type::client:
				active_cipher_->set_key(client_write_key);
				record_nonce ^= client_write_iv;
				break;
			case endpoint_type::server:
				active_cipher_->set_key(server_write_key);
				record_nonce ^= server_write_iv;
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
		return active_cipher_->encrypt(record_nonce, {header, std::nullopt, std::endian::big}, {fragment, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}

	byte_string traffic_secret_manager::decrypt(const byte_string_view header, const byte_string_view fragment) {
		big_unsigned record_nonce(read_nonce++, active_cipher_->iv_length * 8);
		switch (endpoint_type_) {
			case endpoint_type::client:
				active_cipher_->set_key(server_write_key);
				record_nonce ^= server_write_iv;
				break;
			case endpoint_type::server:
				active_cipher_->set_key(client_write_key);
				record_nonce ^= client_write_iv;
				break;
			default:
				throw std::runtime_error("unexpected");
		}
		return active_cipher_->decrypt(record_nonce, {header, std::nullopt, std::endian::big}, {fragment, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}

	constexpr std::uint8_t
			empty[] = "", key[] = "key", iv[] = "iv", derived[] = "derived", c_e_traffic[] = "c e traffic",
			c_hs_traffic[] = "c hs traffic", s_hs_traffic[] = "s hs traffic", c_ap_traffic[] = "c ap traffic",
			s_ap_traffic[] = "s ap traffic", traffic_upd[] = "traffic upd";

	void traffic_secret_manager::update_client_key_iv_(const byte_string_view write_secret) {
		client_write_key = {active_cipher_->HKDF_expand_label(write_secret, key, empty, active_cipher_->key_length), std::nullopt, std::endian::big};
		client_write_iv = {active_cipher_->HKDF_expand_label(write_secret, iv, empty, active_cipher_->iv_length), std::nullopt, std::endian::big};
	}

	void traffic_secret_manager::update_server_key_iv_(const byte_string_view write_secret) {
		server_write_key = {active_cipher_->HKDF_expand_label(write_secret, key, empty, active_cipher_->key_length), std::nullopt, std::endian::big};
		server_write_iv = {active_cipher_->HKDF_expand_label(write_secret, iv, empty, active_cipher_->iv_length), std::nullopt, std::endian::big};
	}

	void traffic_secret_manager::reset_nonce_(const bool __s, const bool __c) {
		switch (endpoint_type_) {
			case endpoint_type::client:
				if (__c)
					write_nonce = 0;
				if (__s)
					read_nonce = 0;
				break;
			case endpoint_type::server:
				if (__c)
					read_nonce = 0;
				if (__s)
					write_nonce = 0;
				break;
			default:
				throw std::runtime_error("unexpected");
		}
	}

	void traffic_secret_manager::update_entropy_secret(const byte_string_view source) {
		switch (secret_state_) {
			case secret_state_t::init:
				// source is pre_shared_key or empty
				entropy_secret_ = active_cipher_->HMAC_hash(
						source.empty() ? byte_string(active_cipher_->digest_length, 0) : source, empty);
				secret_state_ = secret_state_t::early;
				break;
			case secret_state_t::early:
				// source is shared key after key exchange
				entropy_secret_ = active_cipher_->HMAC_hash(
						source,
						active_cipher_->derive_secret(entropy_secret_, derived, empty));
				secret_state_ = secret_state_t::handshake;
				break;
			case secret_state_t::handshake:
				// source is empty
				entropy_secret_ = active_cipher_->HMAC_hash(byte_string(active_cipher_->digest_length, 0),
						active_cipher_->derive_secret(entropy_secret_, derived, empty));
				secret_state_ = secret_state_t::master;
				break;
			case secret_state_t::master:
				entropy_secret_.clear();
				secret_state_ = secret_state_t::application;
				break;
			default:
				throw std::runtime_error("unexpected");
		}
	}

	std::pair<bool, bool> get_update_type(const traffic_secret_manager::update_t __t) {
		return {static_cast<int>(__t) & static_cast<int>(traffic_secret_manager::update_t::server), static_cast<int>(__t) & static_cast<int>(traffic_secret_manager::update_t::client)};
	}

	void traffic_secret_manager::update_early_key(const byte_string_view __msg, const update_t __t) {
		if (secret_state_ != secret_state_t::early)
			throw std::runtime_error("entropy secret not up to date");
		const auto [__s, __c] = get_update_type(__t);
		if (__c)
			update_client_key_iv_(active_cipher_->derive_secret(entropy_secret_, c_e_traffic, __msg));
		reset_nonce_(__s, __c);
	}

	void traffic_secret_manager::update_handshake_key(const byte_string_view __msg, const update_t __t) {
		if (secret_state_ != secret_state_t::handshake)
			throw std::runtime_error("entropy secret not up to date");
		const auto [__s, __c] = get_update_type(__t);
		if (__c) {
			client_traffic_secret = active_cipher_->derive_secret(entropy_secret_, c_hs_traffic, __msg);
			update_client_key_iv_(client_traffic_secret);
		}
		if (__s) {
			server_traffic_secret = active_cipher_->derive_secret(entropy_secret_, s_hs_traffic, __msg);
			update_server_key_iv_(server_traffic_secret);
		}
		reset_nonce_(__s, __c);
	}

	void traffic_secret_manager::update_master_key(const byte_string_view __msg, const update_t __t) {
		if (secret_state_ != secret_state_t::master)
			throw std::runtime_error("entropy secret not up to date");
		const auto [__s, __c] = get_update_type(__t);
		if (__c) {
			client_traffic_secret = active_cipher_->derive_secret(entropy_secret_, c_ap_traffic, __msg);
			update_client_key_iv_(client_traffic_secret);
		}
		if (__s) {
			server_traffic_secret = active_cipher_->derive_secret(entropy_secret_, s_ap_traffic, __msg);
			update_server_key_iv_(server_traffic_secret);
		}
		reset_nonce_(__s, __c);
	}

	void traffic_secret_manager::update_application_key() {
		if (secret_state_ != secret_state_t::application)
			throw std::runtime_error("entropy secret not up to date");
		client_traffic_secret
			= active_cipher_->HKDF_expand_label(client_traffic_secret, traffic_upd, empty, active_cipher_->digest_length);
		server_traffic_secret
			= active_cipher_->HKDF_expand_label(server_traffic_secret, traffic_upd, empty, active_cipher_->digest_length);
		reset_nonce_(true, true);
	}
}

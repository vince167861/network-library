#include "tls-context/context.h"

namespace leaf::network::tls {
	context::context(const protocol_version_t v, client& c, const endpoint_type_t t)
			: endpoint_type(t), endpoint_version(v), client_(c) {
	}

	void context::use_group(const named_group_t ng) {
		for (const auto& m: managers)
			if (m->group == ng) {
				active_manager_ = m;
				break;
			}
		if (active_manager_) {
			managers.clear();
			managers.push_back(active_manager_);
		}
	}

	key_exchange_manager& context::active_manager() const {
		return *active_manager_;
	}

	void context::use_cipher(const cipher_suite_t cs) {
		for (auto& c: cipher_suites)
			if (c->value == cs) {
				active_cipher_ = c;
				break;
			}
	}

	cipher_suite& context::active_cipher() const {
		return *active_cipher_;
	}

	void context::update_key_iv() {
		std::string server_write_secret, client_write_secret;
		switch (endpoint_type) {
			case endpoint_type_t::client:
				if (client_state_t::start <= client_state && client_state <= client_state_t::wait_server_hello) {
					client_write_secret = client_early_traffic_secret.to_bytes();
				}
				if (client_state_t::wait_encrypted_extensions <= client_state && client_state <= client_state_t::wait_cert_verify) {
					server_write_secret = server_handshake_traffic_secret.to_bytes();
				}
				if (client_state_t::wait_encrypted_extensions <= client_state && client_state <= client_state_t::wait_finish) {
					client_write_secret = client_handshake_traffic_secret.to_bytes();
				}
				if (client_state_t::connected == client_state) {
					server_write_secret = server_application_traffic_secret.to_bytes();
					client_write_secret = client_application_traffic_secret.to_bytes();
				}
				break;
			case endpoint_type_t::server:
				switch (server_state) {
					case server_state_t::recvd_client_hello:
					case server_state_t::negotiated:
						server_write_secret = server_handshake_traffic_secret.to_bytes();
						break;
				}
		}
		server_write_key = var_unsigned::from_bytes(active_cipher_->HKDF_expand_label(server_write_secret, "key", "", active_cipher_->key_length));
		server_write_iv = var_unsigned::from_bytes(active_cipher_->HKDF_expand_label(server_write_secret, "iv", "", active_cipher_->iv_length));
		client_write_key = var_unsigned::from_bytes(active_cipher_->HKDF_expand_label(client_write_secret, "key", "", active_cipher_->key_length));
		client_write_iv = var_unsigned::from_bytes(active_cipher_->HKDF_expand_label(client_write_secret, "iv", "", active_cipher_->iv_length));
		read_nonce = write_nonce = 0;
	}

	std::string context::encrypt(std::string_view header, std::string_view fragment) {
		var_unsigned record_nonce(active_cipher_->iv_length * 8);
		{
			const var_unsigned* sender_write_key = nullptr, * sender_write_iv = nullptr;
			switch (endpoint_type) {
				case endpoint_type_t::client:
					sender_write_key = &client_write_key;
					sender_write_iv = &client_write_iv;
					break;
				case context::endpoint_type_t::server:
					sender_write_key = &server_write_key;
					sender_write_iv = &server_write_iv;
					break;
			}
			record_nonce.set(fixed_unsigned(write_nonce++));
			record_nonce ^= *sender_write_iv;
			active_cipher_->set_key(*sender_write_key);
		}
		return active_cipher_->encrypt(record_nonce.to_bytes(), header, fragment);
	}

	std::string context::decrypt(std::string_view header, std::string_view fragment) {
		var_unsigned record_nonce(active_cipher_->iv_length * 8);
		{
			const var_unsigned* sender_write_key = nullptr, * sender_write_iv = nullptr;
			switch (endpoint_type) {
				case endpoint_type_t::client:
					sender_write_key = &server_write_key;
					sender_write_iv = &server_write_iv;
					break;
				case endpoint_type_t::server:
					sender_write_key = &client_write_key;
					sender_write_iv = &client_write_iv;
					break;
			}
			record_nonce.set(fixed_unsigned(read_nonce++));
			record_nonce ^= *sender_write_iv;
			active_cipher_->set_key(*sender_write_key);
		}
		return active_cipher_->decrypt(record_nonce.to_bytes(), header, fragment);
	}
}

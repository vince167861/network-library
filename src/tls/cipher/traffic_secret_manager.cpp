#include "tls-cipher/traffic_secret_manager.h"
#include "number/flexible.h"

namespace leaf::network::tls {

	traffic_secret_manager::traffic_secret_manager(endpoint_type_t type, std::unique_ptr<cipher_suite>& active)
			: endpoint_type_(type), active_cipher_(active) {
	}

	std::string traffic_secret_manager::encrypt(std::string_view header, std::string_view fragment) {
		big_unsigned record_nonce(write_nonce++, active_cipher_->iv_length * 8);
		switch (endpoint_type_) {
			case endpoint_type_t::client:
				active_cipher_->set_key(client_write_key);
				record_nonce ^= client_write_iv;
				break;
			case endpoint_type_t::server:
				active_cipher_->set_key(server_write_key);
				record_nonce ^= server_write_iv;
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
		return active_cipher_->encrypt(record_nonce, big_unsigned(header), big_unsigned(fragment)).to_bytestring(std::endian::big);
	}

	std::string traffic_secret_manager::decrypt(const std::string_view header, const std::string_view fragment) {
		big_unsigned record_nonce(0, active_cipher_->iv_length * 8);
		{
			const big_unsigned* sender_write_key, * sender_write_iv;
			switch (endpoint_type_) {
				case endpoint_type_t::client:
					sender_write_key = &server_write_key;
					sender_write_iv = &server_write_iv;
					break;
				case endpoint_type_t::server:
					sender_write_key = &client_write_key;
					sender_write_iv = &client_write_iv;
					break;
				default:
					throw std::runtime_error{"unexpected"};
			}
			record_nonce.set(big_unsigned(read_nonce++));
			record_nonce ^= *sender_write_iv;
			active_cipher_->set_key(*sender_write_key);
		}
		return active_cipher_->decrypt(record_nonce, big_unsigned(header), big_unsigned(fragment)).to_bytestring(std::endian::big);
	}

	void traffic_secret_manager::update_client_key_iv_(std::string_view write_secret) {
		client_write_key = big_unsigned(active_cipher_->HKDF_expand_label(write_secret, "key", "", active_cipher_->key_length));
		client_write_iv = big_unsigned(active_cipher_->HKDF_expand_label(write_secret, "iv", "", active_cipher_->iv_length));
	}

	void traffic_secret_manager::update_server_key_iv_(std::string_view write_secret) {
		server_write_key = big_unsigned(active_cipher_->HKDF_expand_label(write_secret, "key", "", active_cipher_->key_length));
		server_write_iv = big_unsigned(active_cipher_->HKDF_expand_label(write_secret, "iv", "", active_cipher_->iv_length));
	}

	void traffic_secret_manager::update_entropy_secret(std::string_view source) {
		switch (secret_state_) {
			case secret_state_t::init:
				// source is pre_shared_key or empty
				entropy_secret_ = active_cipher_->HMAC_hash(
						source.empty() ? std::string(active_cipher_->digest_length, 0) : source,
						"");
				secret_state_ = secret_state_t::early;
				break;
			case secret_state_t::early:
				// source is shared key after key exchange
				entropy_secret_ = active_cipher_->HMAC_hash(
						source,
						active_cipher_->derive_secret(entropy_secret_, "derived", ""));
				secret_state_ = secret_state_t::handshake;
				break;
			case secret_state_t::handshake:
				// source is empty
				entropy_secret_ = active_cipher_->HMAC_hash(
						std::string(active_cipher_->digest_length, 0),
						active_cipher_->derive_secret(entropy_secret_, "derived", ""));
				secret_state_ = secret_state_t::master;
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
	}

	void traffic_secret_manager::update_key_iv(std::string_view handshake_msgs, update_t type) {
		bool update_server = static_cast<int>(type) & static_cast<int>(update_t::server);
		bool update_client = static_cast<int>(type) & static_cast<int>(update_t::client);
		switch (secret_state_) {
			case secret_state_t::early:
				if (update_client)
					update_client_key_iv_(active_cipher_->derive_secret(entropy_secret_, "c e traffic", handshake_msgs));
				break;
			case secret_state_t::handshake:
				if (update_client) {
					client_handshake_traffic_secret
							= active_cipher_->derive_secret(entropy_secret_, "c hs traffic", handshake_msgs);
					update_client_key_iv_(client_handshake_traffic_secret);
				}
				if (update_server) {
					server_handshake_traffic_secret
							= active_cipher_->derive_secret(entropy_secret_, "s hs traffic", handshake_msgs);
					update_server_key_iv_(server_handshake_traffic_secret);
				}
				break;
			case secret_state_t::master:
				if (update_client)
					update_client_key_iv_(active_cipher_->derive_secret(entropy_secret_, "c ap traffic", handshake_msgs));
				if (update_server)
					update_server_key_iv_(active_cipher_->derive_secret(entropy_secret_, "s ap traffic", handshake_msgs));
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
		switch (endpoint_type_) {
			case endpoint_type_t::client:
				if (update_client)
					write_nonce = 0;
				if (update_server)
					read_nonce = 0;
				break;
			case endpoint_type_t::server:
				if (update_client)
					read_nonce = 0;
				if (update_server)
					write_nonce = 0;
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
	}
}

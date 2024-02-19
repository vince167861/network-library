#pragma once
#include "tls-cipher/cipher_suite.h"
#include "number/big_number.h"
#include "common.h"
#include <memory>

namespace leaf::network::tls {

	class traffic_secret_manager {

		endpoint_type_t endpoint_type_;

		std::unique_ptr<cipher_suite>& active_cipher_;

		byte_string entropy_secret_;

		enum class secret_state_t {
			init, early, handshake, master
		} secret_state_ = secret_state_t::init;

		void update_client_key_iv_(byte_string_view write_secret);

		void update_server_key_iv_(byte_string_view write_secret);

	public:
		enum class update_t {
			client = 1, server = 2, both = 3
		};

		big_unsigned server_write_key, server_write_iv, client_write_key, client_write_iv;

		byte_string server_handshake_traffic_secret, client_handshake_traffic_secret;

		std::uint64_t read_nonce = 0, write_nonce = 0;

		traffic_secret_manager(endpoint_type_t, std::unique_ptr<cipher_suite>&);

		byte_string encrypt(byte_string_view header, byte_string_view fragment);

		byte_string decrypt(byte_string_view header, byte_string_view fragment);

		void update_key_iv(byte_string_view handshake_msgs, update_t type = update_t::both);

		void update_entropy_secret(byte_string_view source = {});
	};
}

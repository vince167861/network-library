#pragma once

#include "shared/client.h"
#include "tls-key/manager.h"
#include "tls-cipher/cipher_suite.h"

#include <memory>
#include <list>

namespace leaf::network::tls {

	class context {
		std::shared_ptr<key_exchange_manager> active_manager_;

		std::shared_ptr<cipher_suite> active_cipher_;

	public:
		enum class endpoint_type_t: std::uint8_t {
			server, client
		} endpoint_type;

		enum class client_state_t: std::uint8_t {
			start, wait_server_hello, wait_encrypted_extensions, wait_cert_request, wait_cert,
			wait_cert_verify, wait_finish, wait_key_update, connected, wait_closed, closed
		} client_state = client_state_t::start;

		enum class server_state_t: std::uint8_t {
			start, recvd_client_hello, negotiated, wait_eo_early_data, wait_flight2, wait_cert, wait_cert_verify,
			wait_finished, connected
		} server_state = server_state_t::start;

		protocol_version_t endpoint_version;

		client& client_;

		std::list<std::shared_ptr<key_exchange_manager>> managers;

		std::list<std::shared_ptr<cipher_suite>> cipher_suites;

		random_t random = {0};

		std::string session_id;

		uint64_t read_nonce = 0, write_nonce = 0;

		std::string pre_shared_key;

		var_unsigned
				binder_key, client_early_traffic_secret, early_exporter_master_secret,
				client_handshake_traffic_secret, server_handshake_traffic_secret,
				client_application_traffic_secret, server_application_traffic_secret;

		var_unsigned server_write_key, server_write_iv, client_write_key, client_write_iv;

		context(protocol_version_t, client&, endpoint_type_t);

		void use_group(named_group_t ng);

		void use_cipher(cipher_suite_t);

		void update_key_iv();

		std::string encrypt(std::string_view header, std::string_view fragment);

		std::string decrypt(std::string_view header, std::string_view fragment);

		key_exchange_manager& active_manager() const;

		cipher_suite& active_cipher() const;
	};
}

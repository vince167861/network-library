#pragma once

#include "basic_client.h"
#include "tls-record/handshake.h"
#include "tls-key/manager.h"
#include "tls-record/record.h"
#include "tls-context/endpoint.h"
#include "tls-utils/rng.h"
#include "tls-cipher/cipher_suite.h"
#include "tls-cipher/traffic_secret_manager.h"

#include <memory>
#include <sstream>
#include <optional>
#include <list>

namespace leaf::network::tls {

	class client final: public network::client, public endpoint {

		enum class client_state_t: std::uint8_t {
			wait_server_hello, wait_encrypted_extensions, wait_cert_request, wait_cert,
			wait_cert_verify, wait_finish, wait_key_update, connected, wait_closed, closed
		};

		network::client& client_;

		std::map<named_group_t, std::unique_ptr<key_exchange_manager>> available_managers_;

		std::set<named_group_t> available_groups_;

		std::set<cipher_suite_t> available_cipher_suites_;

		std::unique_ptr<client_hello> gen_client_hello_() const;

		void handshake_();

	public:
		std::optional<std::string> init_session_id;

		std::optional<random_t> init_random;

		std::optional<std::string> server_name;

		std::list<std::string> alpn_protocols;

		explicit client(network::client& client, std::unique_ptr<random_number_generator> generator = std::make_unique<mt19937_uniform>());

		bool connect(std::string_view host, std::uint16_t port) override;

		std::size_t available() override;

		void add_group(std::initializer_list<named_group_t>);

		void add_cipher_suite(std::initializer_list<cipher_suite_t>);

		void reset();
	};

}

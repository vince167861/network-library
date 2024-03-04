#pragma once
#include "tls/endpoint.h"
#include "tls-record/handshake.h"
#include "tls/key/manager.h"
#include <optional>

namespace network::tls {

	class client final: public endpoint, public stream_client {

		enum class client_state_t: std::uint8_t {
			wait_server_hello, wait_encrypted_extensions, wait_cert_request, wait_cert, wait_cert_verify, wait_finish,
			wait_key_update, connected, wait_closed, closed
		};

		stream_client& client_;

		std::map<named_group_t, std::unique_ptr<key_exchange_manager>> available_managers_{};

		std::set<named_group_t> available_groups_{};

		std::set<cipher_suite_t> available_cipher_suites_{};

		std::unique_ptr<client_hello> gen_client_hello_() const;

		void handshake_();

	public:
		std::optional<byte_string> init_session_id;

		std::optional<random_t> init_random;

		std::optional<std::string> server_name;

		std::list<std::string> alpn_protocols{};

		explicit client(stream_client&, std::unique_ptr<random_source> = std::make_unique<mt19937_uniform>());

		void connect(std::string_view host, tcp_port_t port) override;

		std::size_t available() override;

		void add_group(named_group_t, bool generate = true);

		void add_cipher_suite(std::initializer_list<cipher_suite_t>);

		void reset();
	};

}

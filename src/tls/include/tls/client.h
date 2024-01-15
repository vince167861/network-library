#pragma once

#include "shared/client.h"
#include "tls-handshake/handshake.h"
#include "tls-key/manager.h"
#include "tls-record/record.h"
#include "tls-context/context.h"
#include "tls-utils/rng.h"

#include <memory>
#include <sstream>
#include <optional>

namespace leaf::network::tls {

	class client final: public network::client, context {
	public:
		bool compatibility_mode = false;

		std::optional<std::string> server_name, init_session_id;

	private:
		std::stringstream app_data_buffer;

		bool random_random = true;

		std::list<std::string> alpn_protocols;

		client_hello gen_client_hello() const;

		void handshake();

		void send(const record&) const;

	public:
		const std::shared_ptr<random_number_generator> random_generator;

		explicit client(network::client& client, std::shared_ptr<random_number_generator> generator = std::make_shared<mt19937_uniform>());

		void reset();

		bool connect(std::string_view host, unsigned short port) override;

		bool connected() const override;

		std::string read(std::size_t size) override;

		std::size_t write(std::string_view) override;

		bool finish() override;

		void close() override;

		std::size_t available() override;

		void add_group(key_exchange_manager*);

		void add_group(std::string_view);

		void mock_group(named_group_t);

		void add_cipher(cipher_suite*);

		void add_cipher(std::string_view);

		void mock_cipher(cipher_suite_t);

		void set_random(std::string_view bytes);

		void add_alpn(std::string_view);
	};

}

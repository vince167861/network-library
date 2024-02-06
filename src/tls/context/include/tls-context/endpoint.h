#pragma once

#include "basic_client.h"

#include "tls-key/manager.h"
#include "tls-cipher/cipher_suite.h"
#include "tls-record/record.h"
#include "tls-context/endpoint.h"
#include "tls-utils/rng.h"
#include "tls-cipher/traffic_secret_manager.h"

#include <memory>
#include <list>
#include <sstream>
#include <optional>

namespace leaf::network::tls {

	struct client_hello;

	class endpoint: virtual public network::endpoint {
	protected:
		std::unique_ptr<key_exchange_manager> active_manager_;

		std::unique_ptr<cipher_suite> active_cipher_;

		std::stringstream app_data_buffer;

		traffic_secret_manager cipher_;

	public:
		network::endpoint& underlying;

		protocol_version_t endpoint_version = protocol_version_t::TLS1_3;

		random_t random = {0};

		std::string session_id;

		std::string pre_shared_key;

		endpoint(network::endpoint& endpoint, endpoint_type_t, std::unique_ptr<random_number_generator> generator = std::make_unique<mt19937_uniform>());

		std::string read(std::size_t size) override;

		std::size_t write(std::string_view) override;

		void send_(const record&);

		void use_group(named_group_t);

		void use_group(std::unique_ptr<key_exchange_manager>);

		void use_cipher(cipher_suite_t);

		key_exchange_manager& active_manager() const {
			return *active_manager_;
		}

		cipher_suite& active_cipher_suite() const {
			return *active_cipher_;
		}

		traffic_secret_manager& cipher() {
			return cipher_;
		}

		void finish() override;

		void close() override;

		const std::unique_ptr<random_number_generator> random_generator;

		bool compatibility_mode = false;

		bool connected() const override {
			return underlying.connected();
		}
	};
}

#pragma once

#include "basic_endpoint.h"

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

	class endpoint: virtual public network::endpoint {
	protected:
		std::unique_ptr<key_exchange_manager> active_manager_;

		std::unique_ptr<cipher_suite> active_cipher_;

		string_stream app_data_buffer;

		traffic_secret_manager cipher_;

		void send_(const record&);

		void send_(content_type_t, bool encrypted, std::initializer_list<std::unique_ptr<message>>);

	public:
		network::endpoint& underlying;

		protocol_version_t endpoint_version = protocol_version_t::TLS1_3;

		random_t random = {0};

		byte_string session_id;

		byte_string pre_shared_key;

		endpoint(network::endpoint& endpoint, endpoint_type_t, std::unique_ptr<random_number_generator> generator = std::make_unique<mt19937_uniform>());

		byte_string read(std::size_t size) override;

		std::uint8_t read() override;

		void write(std::uint8_t octet) override;

		void write(byte_string_view) override;

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

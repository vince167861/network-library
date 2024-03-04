#pragma once
#include "stream_endpoint.h"
#include "random_source.h"
#include "key/manager.h"
#include "tls-record/record.h"
#include "cipher/cipher_suite.h"
#include "cipher/traffic_secret_manager.h"
#include <memory>

namespace network::tls {

	class endpoint: virtual public stream_endpoint {
	protected:
		stream_endpoint& base_;

		std::unique_ptr<key_exchange_manager> key_exchange_;

		std::unique_ptr<cipher_suite> cipher_;

		traffic_secret_manager secret_;

		const std::unique_ptr<random_source> random_;

		string_stream app_data_;

		void send_(const record&);

		void send_(content_type_t, bool encrypted, std::initializer_list<std::unique_ptr<message>>);

	public:
		protocol_version_t endpoint_version = protocol_version_t::TLS1_3;

		random_t random{};

		byte_string session_id;

		byte_string pre_shared_key;

		endpoint(stream_endpoint&, endpoint_type, std::unique_ptr<random_source> = std::make_unique<::mt19937_uniform>());

		[[nodiscard]] bool
		connected() const override {
			return base_.connected();
		}

		byte_string read(std::size_t size) override;

		std::uint8_t read() override;

		void write(std::uint8_t octet) override;

		void write(byte_string_view) override;

		void finish() override;

		void close() override;

		void use_group(named_group_t);

		void use_group(std::unique_ptr<key_exchange_manager>);

		void use_cipher(cipher_suite_t);

		[[nodiscard]] key_exchange_manager&
		key_exchange() const {
			return *key_exchange_;
		}

		[[nodiscard]] cipher_suite&
		cipher() const {
			return *cipher_;
		}

		[[nodiscard]] traffic_secret_manager&
		secret() {
			return secret_;
		}

		bool compatibility_mode = false;
	};
}

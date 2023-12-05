#pragma once

#include "base_client.h"

#include <ws2tcpip.h>

namespace leaf::network::tcp {


	class client: public base_client {

		bool connected_ = false;

		SOCKET socket_ = INVALID_SOCKET;

		[[noreturn]] static void throw_error(std::string_view function);

	public:
		client();

		bool connect(std::string_view host, uint16_t port) override;

		bool connected() const override;

		std::string read(std::size_t size) override;

		std::size_t write(std::string_view buffer) override;

		bool finish() override;

		void close() override;

		std::size_t available() override;

		~client();
	};
}

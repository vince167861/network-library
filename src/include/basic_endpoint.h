#pragma once
#include <cstdint>
#include <string_view>

namespace network {

	enum class endpoint_type {
		server, client
	};

	struct basic_endpoint {

		[[nodiscard]] virtual bool connected() const = 0;

		virtual void finish() = 0;

		virtual void close() = 0;

		virtual ~basic_endpoint() = default;
	};

	using tcp_port_t = std::uint16_t;

	struct basic_client: virtual basic_endpoint {

		virtual void connect(std::string_view host, tcp_port_t) = 0;

		virtual std::size_t available() = 0;
	};

	struct basic_server {

		virtual void listen(tcp_port_t, std::size_t max_connection) = 0;

		virtual void close() = 0;

		virtual ~basic_server() = default;
	};
}

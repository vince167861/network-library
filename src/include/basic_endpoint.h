#pragma once
#include "byte_stream.h"
#include <memory>

namespace leaf::network {

	struct endpoint: virtual stream {

		virtual bool connected() const = 0;

		virtual void finish() = 0;

		virtual void close() = 0;

		/**
		 * \brief Read until connection closed
		 */
		virtual byte_string read_all() {
			byte_string str;
			while (connected()) {
				try {
					str += read(50);
				} catch (...) {
					break;
				}
			}
			return str;
		}
	};

	using tcp_port_t = std::uint16_t;


	struct client: virtual endpoint {

		virtual bool connect(std::string_view host, tcp_port_t) = 0;

		virtual std::size_t available() = 0;
	};


	struct server {

		virtual void listen(tcp_port_t, std::size_t max_connection) = 0;

		virtual std::unique_ptr<endpoint> accept() = 0;

		virtual void close() = 0;
	};
}

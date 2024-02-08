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
		virtual std::string read_all() {
			std::string str;
			while (connected()) {
				try {
					str += read(50);
				} catch (const std::exception&) {
					break;
				}
			}
			return str;
		}
	};


	struct client: virtual endpoint {

		virtual bool connect(std::string_view host, std::uint16_t port) = 0;

		virtual std::size_t available() = 0;
	};


	struct server {

		virtual void listen(std::uint16_t port, std::size_t max_connection) = 0;

		virtual std::unique_ptr<endpoint> accept() = 0;

		virtual void close() = 0;
	};
}

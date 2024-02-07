#pragma once
#include "basic_endpoint.h"
#include <cstdint>

namespace leaf::network {

	class client: virtual public endpoint {
	public:

		virtual bool connect(std::string_view host, std::uint16_t port) = 0;

		virtual std::size_t available() = 0;

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
}

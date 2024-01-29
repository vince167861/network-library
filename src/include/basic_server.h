#pragma once

#include "basic_endpoint.h"

#include <memory>
#include <cstdint>

namespace leaf::network {

	class server {
	public:
		virtual void listen(std::uint16_t port, std::size_t max_connection) = 0;

		virtual std::unique_ptr<endpoint> accept() = 0;

		virtual void close() = 0;
	};
}

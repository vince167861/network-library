#pragma once
#include "basic_endpoint.h"
#include "http/message.h"
#include <list>

namespace leaf::network::http {

	class client {

		network::client& underlying_;

		std::string connected_host_;

		tcp_port_t connected_port_ = 0;

		void connect_(std::string_view host, tcp_port_t port);

	public:
		explicit client(network::client& c)
			: underlying_(c) {
		}

		response fetch(request);
	};
}

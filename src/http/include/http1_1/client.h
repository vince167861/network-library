#pragma once
#include "stream_endpoint.h"
#include "http/message.h"

namespace network::http {

	struct client {

		explicit client(stream_client& c, const bool secured)
			: base_(c), secured_(secured) {
		}

		response fetch(request);

	private:
		stream_client& base_;

		const bool secured_;

		std::string connected_host_;

		tcp_port_t connected_port_{};

		void connect_(std::string_view host, tcp_port_t port);
	};
}

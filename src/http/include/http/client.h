#pragma once

#include "basic_endpoint.h"
#include "http/message.h"
#include "http/event_stream.h"

#include <optional>
#include <future>
#include <list>

namespace leaf::network::http {

	class client {

		network::client& client_;

		std::string connected_host_;

		std::uint16_t connected_port_ = 0;

		std::list<std::pair<request, std::promise<response>>>
		pending_response_;

		bool connect_(std::string_view host, uint16_t port);

		void send_(const request&);

	public:
		explicit client(network::client&);

		std::future<response> fetch(const request&);

		event_source stream(request);

		void process();
	};

}

#pragma once

#include "basic_client.h"
#include "http/request.h"
#include "http/response.h"
#include "http/event_stream.h"

#include <optional>
#include <future>
#include <list>

namespace leaf::network::http {

	class client {
		network::client& client_;

		std::optional<std::pair<std::string, uint16_t>> connected_remote_;

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

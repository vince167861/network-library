#pragma once

#include "shared/client.h"
#include "http/request.h"
#include "http/response.h"

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

	public:
		explicit client(network::client&);

		std::future<response> send(const request&);

		void process();
	};

}

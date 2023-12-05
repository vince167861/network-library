#pragma once

#include <future>

#include "shared/client.h"
#include "http2/context.h"
#include "http2/frame.h"
#include "http2/request.h"
#include "http2/response.h"

namespace leaf::network::http2 {

	class client: public context {
		network::client& client_;

		std::map<uint32_t, std::pair<response, std::promise<response>>>
		pending_requests_;

		std::string connected_host_;

		long connected_port_ = 0;

		bool connect(std::string_view host, uint16_t port);

		void process_settings(const std::list<std::pair<settings_t, uint32_t>>&);

	public:
		explicit client(network::client&);

		std::future<response> send(const request&);

		void send(const frame&);

		void process();
	};


	class stream_error final: public std::exception {
	public:
		error_t code;

		explicit stream_error(error_t);
	};
}

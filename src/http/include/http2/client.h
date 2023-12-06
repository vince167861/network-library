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

		std::optional<std::pair<std::string, uint16_t>> connected_remote_;

		std::optional<uint32_t> closing_;

		bool connect(std::string_view host, uint16_t port);

		void close(error_t error_code = error_t::no_error, std::string_view additional = "");

		void process_settings(const std::list<std::pair<settings_t, uint32_t>>&);

	public:
		explicit client(network::client&);

		std::future<response> send(const request&);

		bool send(const frame&) const;

		void process();

		~client();
	};


	class stream_error final: public std::exception {
	public:
		error_t code;

		explicit stream_error(error_t);
	};
}

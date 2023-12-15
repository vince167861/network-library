#pragma once

#include "http2/frame.h"
#include "http/request.h"
#include "http2/response.h"
#include "http2/context.h"

#include <cstdint>

namespace leaf::network::http2 {

	class stream_handler {
	public:
		enum class state_t {
			idle, local_reserved, remote_reserved, open, local_half_closed, remote_half_closed, local_closed,
			remote_closed
		};

	private:
		state_t state_;

		context& context_;

		uint32_t stream_id_;

		uint32_t window_bytes_;

		http::request request_;

		response response_;

		std::promise<response> pending_promise_;

	public:
		stream_handler(uint32_t stream_id, context&, state_t state);

		void send_request(stream&, const http::request&);

		task<void> send(stream&, std::shared_ptr<stream_frame>);

		void handle(const stream_frame&);

		uint32_t get_available_window();

		std::future<response> get_future();

		state_t state() const;

		void close(stream&);
	};
}

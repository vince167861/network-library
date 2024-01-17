#pragma once

#include "http2/frame.h"
#include "http/request.h"
#include "http/response.h"
#include "http2/context.h"
#include "shared/task.h"

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

		stream_id_t stream_id_;

		uint32_t window_bytes_;

		http::request request_;

		http::response response_;

		std::promise<http::response> pending_promise_;

		std::list<std::reference_wrapper<stream_handler>> promised_stream_;

	public:
		stream_handler(stream_id_t, context&, state_t);

		void send_request(stream&, const http::request&);

		task<void> send(stream&, const frame&);

		void open(http::http_fields, bool end_stream);

		void reserve(stream_id_t, http::http_fields);

		void notify(std::string_view, bool end_stream);

		void reset();

		void increase_window(std::uint32_t);

		std::uint32_t get_available_window() const;

		std::future<http::response> get_future();

		state_t state() const;

		void close(stream&);
	};
}

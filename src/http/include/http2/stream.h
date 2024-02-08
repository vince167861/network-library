#pragma once

#include "http/message.h"
#include "http/event_stream.h"
#include "http2/frame.h"
#include "http2/context.h"
#include "task.h"

#include <cstdint>
#include <sstream>

namespace leaf::network::http2 {

	class stream_handler {
	public:
		enum class state_t {
			idle, local_reserved, remote_reserved, open, local_half_closed, remote_half_closed, closed
		};

	protected:
		state_t state_;

		context& context_;

		stream_id_t stream_id_;

		uint32_t window_bytes_;

		http::request request_;

		std::list<std::reference_wrapper<stream_handler>> promised_stream_;

		task<void> write_to_(stream&, const frame&);

		void write_request_to_(stream&);

		stream_handler(stream_id_t, context&, state_t);

	public:
		virtual void notify(const http::http_fields&, const bool end_stream) = 0;

		virtual void notify(std::string_view, bool end_stream) = 0;

		virtual void reserve(stream_id_t, http::http_fields) = 0;

		virtual void reset() = 0;

		void increase_window(std::uint32_t);

		std::uint32_t get_available_window() const;

		state_t state() const;

		stream_id_t stream_id() const;

		void write_close_to_(stream& s);

		void set_local_closed_();

		void set_remote_closed_();

		virtual ~stream_handler() = default;
	};


	class response_handler final: public stream_handler {

		std::promise<http::response> pending_promise_;

		http::response response_;

	public:
		response_handler(stream&, context&, const http::request&);

		response_handler(stream_id_t promised, http::http_fields, context&);

		void notify(const http::http_fields& headers, const bool end_stream) override;

		void notify(std::string_view, bool end_stream) override;

		void reserve(stream_id_t, http::http_fields) override;

		void reset() override;

		std::future<http::response> get_future();
	};


	class event_stream_handler final: public stream_handler {

		std::string buffer_;

	public:
		event_stream_handler(context&, const http::request&);

		http::event_source get_event_source(stream&);

		void notify(const http::http_fields&, const bool end_stream) override;

		void notify(std::string_view, bool end_stream) override;

		void reserve(stream_id_t, http::http_fields) override;

		void reset() override;
	};
}

#pragma once

#include "basic_client.h"
#include "http2/context.h"
#include "http2/frame.h"
#include "http/request.h"
#include "http/response.h"
#include "http/event_stream.h"

#include <future>

namespace leaf::network::http2 {

	class client: public context {

		network::client& client_;

		std::optional<std::pair<std::string, uint16_t>> connected_remote_;

		std::optional<uint32_t> closing_;

		bool connect(std::string_view host, uint16_t port);

		bool connected() const;

		void close(error_t error_code = error_t::no_error, std::string_view additional = "");

		void process_settings(const setting_values_t& settings_f);

		/**
		 * \brief Send connection frames.
		 *
		 * \details Blocking `write_` to write_to_ critical frames of HTTP/2 connections.
		 */
		void write_(const frame& frame) const;

	public:
		explicit client(network::client&);

		std::future<http::response> fetch(const http::request&);

		http::event_source stream(const http::request&);

		void process();

		~client();
	};
}

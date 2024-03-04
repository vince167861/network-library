#pragma once
#include "basic_endpoint.h"
#include "stream_endpoint.h"
#include "http/message.h"
#include "http2/state.h"
#include <future>
#include <unordered_map>

namespace network::http2 {

	struct client final {

		explicit client(stream_client& __c)
				: client_(__c), state_(endpoint_type::client, __c) {
		}

		std::future<http::response> fetch(http::request);

		void process();

		~client();

	private:
		stream_client& client_;

		connection_state state_;

		std::unordered_map<http::request, std::future<http::response>> pushed_;

		void connect_(std::string_view host, tcp_port_t);

		bool connected() const;

		void close(error_t error_code = error_t::no_error, std::string_view additional = "");

		std::string connected_host_;

		tcp_port_t connected_port_ = 0;

		void handle_(const setting_values_t& settings_f);
	};
}

#pragma once
#include "basic_endpoint.h"
#include "http/message.h"
#include "http2/state.h"
#include "http2/frame.h"
#include <future>

namespace leaf::network::http2 {

	class client final {

		network::client& client_;

		connection_state state_;

		std::optional<std::pair<std::string, tcp_port_t>> connected_remote_;

		std::unordered_map<http::request, std::future<http::response>> pushed_;

		void connect(std::string_view host, tcp_port_t);

		bool connected() const;

		void close(error_t error_code = error_t::no_error, std::string_view additional = "");

		void process_settings(const setting_values_t& settings_f);

	public:
		explicit client(network::client&);

		std::future<http::response> fetch(http::request);

		void process();

		~client();
	};
}

#pragma once
#include "basic_endpoint.h"
#include "http/message.h"
#include "http2/state.h"
#include <future>

namespace leaf::network::http2 {

	class client final {

		network::client& client_;

		connection_state state_;

		std::unordered_map<http::request, std::future<http::response>> pushed_;

		void connect(std::string_view host, tcp_port_t);

		bool connected() const;

		void close(error_t error_code = error_t::no_error, std::string_view additional = "");

	public:
		explicit client(network::client&);

		std::future<http::response> fetch(http::request);

		void process();

		~client();

	private:
		std::string connected_host_;

		tcp_port_t connected_port_ = 0;

		void handle_(const setting_values_t& settings_f);
	};
}

#include "http/client.h"

namespace leaf::network::http {

	client::client(network::client& client)
		: client_(client) {
	}

	void client::send(const request& request) {
		if (!client_.connected()) {
			uint16_t port = request.target_url.port;
			if (port == 0) {
				if (request.target_url.scheme == "http")
					port = 80;
				else if (request.target_url.scheme == "https")
					port = 443;
				else {
					request.trigger(request::error_t::unknown_port);
					return;
				}
			}
			if (!client_.connect(request.target_url.host, port)) {
				request.trigger(request::error_t::connect_failed);
				return;
			}
		}
		client_.write(request.build());
		client_.finish();
		handle_(request);
	}

	void client::handle_(const request& request) {
		response response{client_};
		if (response.is_event_stream()) {
			while (client_.connected()) {
				if (client_.available()) {
					std::string event, data;
					for (auto& [field, value]: parse_http_fields(client_)) {
						if (field == "event")
							event = value;
						else if (field == "data")
							data += value + '\n';
					}
					request.trigger(std::pair{event, data});
				}
			}
		} else
			request.trigger(response);
	}

} // leaf

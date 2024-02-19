#include "http/client.h"

#include <list>
#include <algorithm>
#include <ranges>

namespace leaf::network::http {

	const std::runtime_error http_response_syntax_error{"HTTP response syntax error"};

	client::client(network::client& client): client_(client) {}

	bool client::connect_(const std::string_view host, const std::uint16_t port) {
		if (client_.connected() && connected_host_ == host && connected_port_ == port)
			return true;
		client_.close();
		if (!client_.connect(host, port))
			return false;
		connected_host_ = host;
		connected_port_ = port;
		return true;
	}

	void client::send_(const request& __req) {
		std::uint16_t __p = __req.request_url.port;
		if (__p == 0) {
			if (__req.request_url.scheme == "http")
				__p = 80;
			else if (__req.request_url.scheme == "https")
				__p = 443;
			else
				throw std::invalid_argument("unknown scheme or set port explicitly");
		}
		if (!connect_(__req.request_url.host, __p))
			throw std::runtime_error{"Connection failed."};
		auto copy = __req.headers;
		copy.set("host", __req.request_url.host);
		if (!__req.body.empty())
			copy.set("content-length", std::to_string(__req.body.length()));
		const auto req_str = std::format("{} {} HTTP/1.1\r\n{}\r\n{}",
										 __req.method, __req.request_url.requesting_uri_string(), static_cast<std::string>(copy), __req.body);
		client_.write(reinterpret_cast<const byte_string&>(req_str));
	}

	std::future<response> client::fetch(const request& request) {
		auto& [fst, snd] = pending_response_.emplace_back(request, std::promise<response>{});
		return snd.get_future();
	}

	response parse_response_header(istream& __s) {
		response __res;
		const auto __sl = __s.read_line();
		if (!__sl.starts_with("HTTP/") || !__sl.ends_with('\r') || __s.read() != '\n')
			throw http_response_syntax_error;
		auto it = __sl.begin() + 5;

		const auto __v = std::find(it, __sl.end(), ' ');
		if (__v == __sl.end())
			throw http_response_syntax_error;

		auto const __c = std::find(__v + 1, __sl.end(), ' ');
		if (__c == __sl.end())
			throw http_response_syntax_error;

		try {
			__res.status = std::stoi(std::string(__v + 1, __c));
		} catch (...) {
			throw http_response_syntax_error;
		}
		__res.headers = http_fields::from_http_headers(__s);
		return __res;
	}

	void parse_response_body(response& __res, network::client& __s, bool discard = false) {
		// no response body for 1XX, 204, 304
		if (100 <= __res.status && __res.status <= 199 || __res.status == 204 || __res.status == 304)
			return;
		if (__res.headers.contains("transfer-encoding") && __res.headers.at("transfer-encoding").contains("chunked")) {
			while (true) {
				const auto __h = __s.read_line();
				if (!__h.ends_with("\r") || __s.read() != '\n')
					throw http_response_syntax_error;
				const auto __sep = std::find(__h.begin(), __h.end() - 1, ';');
				std::size_t __cl;
				try {
					__cl = std::stoull(std::string{__h.begin(), __sep}, nullptr, 16);
				} catch (...) {
					throw http_response_syntax_error;
				}
				if (__cl == 0)
					break;
				const auto chunk = __s.read(__cl);
				if (__s.read(2) != reinterpret_cast<const std::uint8_t*>("\r\n"))
					throw http_response_syntax_error;
				if (!discard)
					__res.body += reinterpret_cast<const std::string&>(chunk);
			}
			return;
		}
		if (__res.headers.contains("content-length")) {
			std::size_t __len;
			try {
				__len = std::stoull(__res.headers.at("content-length"));
			} catch (...) { throw http_response_syntax_error; }
			if (!discard) {
				const auto __d = __s.read(__len);
				__res.body = reinterpret_cast<const std::string&>(__d);
			} else
				__s.skip(__len);
			return;
		}
		const auto __c = __s.read_all();
		if (!discard)
			__res.body = reinterpret_cast<const std::string&>(__c);
	}

	event_source client::stream(request request) {
		request.headers.set("accept", "text/event-stream");
		while (true) {
			send_(request);
			auto response = parse_response_header(client_);
			if (response.is_redirection()) {
				parse_response_body(response, client_, true);
				if (!response.headers.contains("location"))
					throw std::runtime_error{"Server does not provide \"location\" for a redirection message."};
				request.request_url.replace(response.headers.at("location"));
				continue;
			}
			if (!response.headers.contains("content-type") || !response.headers.at("content-type").starts_with("text/event-stream"))
				throw std::runtime_error{"server does not response with text/event-stream"};
			while (client_.connected()) {
				auto event_data = http_fields::from_event_stream(client_);
				event event;
				if (event_data.contains("event"))
					event.event_type = event_data.at("event");
				if (event_data.contains("data"))
					event.data += event_data.at("data");
				if (event_data.contains("id"))
					event.id = event_data.at("id");
				co_yield event;
			}
			co_return;
		}
	}

	void client::process() {
		for (auto& [request, promise]: pending_response_) {
			send_(request);
			auto response = parse_response_header(client_);
			parse_response_body(response, client_);
			promise.set_value(std::move(response));
		}
		pending_response_.clear();
	}
}

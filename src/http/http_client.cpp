#include "http/client.h"

#include <list>
#include <algorithm>
#include <ranges>

namespace leaf::network::http {

	std::optional<event> event_source::await_next_event() {
		if (this->done())
			return {};
		this->resume();
		std::optional<event> event;
		std::swap(event, promise().received);
		return event;
	}


	const std::runtime_error http_response_syntax_error{"HTTP response syntax error"};

	client::client(network::client& client): client_(client) {}

	bool client::connect_(const std::string_view host, const uint16_t port) {
		if (client_.connected()
				&& connected_remote_.has_value() && connected_remote_.value().first == host
				&& connected_remote_.value().second == port)
			return true;
		client_.close();
		if (!client_.connect(host, port))
			return false;
		connected_remote_.emplace(host, port);
		return true;
	}

	void client::send_(const request& request) {
		std::uint16_t port = request.request_url.port;
		if (port == 0) {
			if (request.request_url.scheme == "http")
				port = 80;
			else if (request.request_url.scheme == "https")
				port = 443;
			else
				throw std::runtime_error{"Scheme unknown; set port explicitly."};
		}
		if (!connect_(request.request_url.host, port))
			throw std::runtime_error{"Connection failed."};
		auto copy = request.headers;
		copy.set("host", request.request_url.host);
		if (!request.body.empty())
			copy.set("content-length", std::to_string(request.body.length()));
		client_.write(std::format("{} {} HTTP/1.1\r\n{}\r\n{}",
			request.method, request.request_url.requesting_uri_string(), static_cast<std::string>(copy), request.body));
	}

	std::future<response> client::fetch(const request& request) {
		auto& [fst, snd] = pending_response_.emplace_back(request, std::promise<response>{});
		return snd.get_future();
	}

	response parse_response_header(network::client& client) {
		response response;
		auto status_line = client.read_until("\n");
		if (!status_line.starts_with("HTTP/") || !status_line.ends_with("\r\n"))
			throw http_response_syntax_error;
		auto begin = status_line.begin() + 5;
		const auto first_whitespace = std::find(begin, status_line.end(), ' ');
		if (first_whitespace == status_line.end())
			throw http_response_syntax_error;
		auto const second_whitespace = std::find(first_whitespace + 1, status_line.end(), ' ');
		if (second_whitespace == status_line.end())
			throw http_response_syntax_error;
		std::string http_version = {begin, first_whitespace};
		try {
			response.status = std::stoi(std::string{first_whitespace + 1, second_whitespace});
		} catch (...) {
			throw http_response_syntax_error;
		}
		response.headers = http_fields::from_http_headers(client);
		return response;
	}

	void parse_response_body(response& response, network::client& client, bool discard = false) {
		// no response body for 1XX, 204, 304
		if (100 <= response.status && response.status <= 199 || response.status == 204 || response.status == 304)
			return;
		if (response.headers.contains("transfer-encoding")
			&& response.headers.at("transfer-encoding").contains("chunked")) {
			while (true) {
				auto chunk_header = client.read_until("\n");
				if (!chunk_header.ends_with("\r\n"))
					throw http_response_syntax_error;
				const auto semicolon
						= std::find(chunk_header.begin(), chunk_header.end() - 2, ';');
				int chunk_length;
				try {
					chunk_length = std::stoi(std::string{chunk_header.begin(), semicolon}, nullptr, 16);
				} catch (...) { throw http_response_syntax_error; }
				if (chunk_length == 0)
					break;
				const auto chunk = client.read(chunk_length);
				if (client.read(2) != "\r\n")
					throw http_response_syntax_error;
				if (!discard)
					response.body += chunk;
			}
		} else if (response.headers.contains("content-length")) {
			std::size_t length;
			try {
				length = std::stoull(response.headers.at("content-length"));
			} catch (...) { throw http_response_syntax_error; }
			if (!discard)
				response.body = client.read(length);
			else
				client.skip(length);
		} else if (!discard)
			response.body = client.read_all();
		else
			client.read_all();
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

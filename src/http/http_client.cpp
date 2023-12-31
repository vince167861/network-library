#include "http/client.h"

#include <list>
#include <algorithm>
#include <ranges>

namespace leaf::network::http {

	const std::runtime_error http_response_syntax_error{"HTTP response syntax error"};

	client::client(network::client& client)
		: client_(client) {
	}

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

	auto client::send(const request& request) -> std::future<response> {
		auto& [fst, snd] = pending_response_.emplace_back(request, std::promise<response>{});
		return snd.get_future();
	}

	void client::process() {
		for (auto& [request, promise]: pending_response_) {
			uint16_t port = request.request_url.port;
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
			std::list<std::pair<std::string, std::string>>
					copy{request.headers.begin(), request.headers.end()};
			copy.emplace_front("host", request.request_url.host);
			if (!request.body.empty())
				copy.emplace_back("content-length", std::to_string(request.body.length()));
			client_.write(request.method);
			client_.write(" ");
			client_.write(request.request_url.path.empty() ? "/" : request.request_url.path);
			if (!request.request_url.query.empty()) {
				client_.write("?");
				client_.write(to_url_encoded(request.request_url.query));
			}
			client_.write(" HTTP/1.1\r\n");
			for (auto& [field, value]: copy) {
				client_.write(field);
				client_.write(": ");
				client_.write(value);
				client_.write("\r\n");
			}
			client_.write("\r\n");
			client_.write(request.body);

			response response;
			auto status_line = client_.read_until('\n');
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
			response.headers = parse_http_fields(client_);
			// no response body for 1XX, 204, 304
			if (!(100 <= response.status && response.status <= 199 || response.status == 204 || response.status == 304)) {
				std::optional<std::string> transfer_encoding, content_length;
				for (auto& [key, value]: response.headers) {
					if (key == "transfer-encoding")
						transfer_encoding = value;
					else if (key == "content-length")
						content_length = value;
				}
				if (transfer_encoding.has_value() && transfer_encoding.value().contains("chunked")) {
					while (true) {
						auto chunk_header = client_.read_until('\n');
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
						const auto chunk = client_.read(chunk_length);
						if (client_.read(2) != "\r\n")
							throw http_response_syntax_error;
						response.body += chunk;
					}
				} else if (content_length.has_value()) {
					std::size_t length;
					try {
						length = std::stoull(content_length.value());
					} catch (...) { throw http_response_syntax_error; }
					response.body = client_.read(length);
				} else {
					response.body = client_.read_all();
				}
			}
			promise.set_value(std::move(response));
		}
		pending_response_.clear();
	}

}

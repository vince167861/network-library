#include "http/response.h"
#include "http/url.h"
#include "http/http_exception.h"

#include <algorithm>

namespace leaf::network::http {

	response::response(client& client) {
		auto&& status_line = client.read_until('\n');
		if (!status_line.starts_with("HTTP/") || !status_line.ends_with("\r\n")) {
			status = -1;
			throw http_response_parse_error();
		}
		auto begin = status_line.begin() + 5;
		auto const first_whitespace = std::find(begin, status_line.end(), ' ');
		if (first_whitespace == status_line.end())
			throw http_response_parse_error();
		auto const second_whitespace = std::find(first_whitespace + 1, status_line.end(), ' ');
		if (second_whitespace == status_line.end())
			throw http_response_parse_error();
		std::string http_version = {begin, first_whitespace};
		try {
			status = std::stoi(std::string{first_whitespace + 1, second_whitespace});
		} catch (const std::exception&) {
			throw http_response_parse_error();
		}
		auto&& response_headers = parse_http_fields(client);
		if (response_headers.contains("content-type")) {
			if (response_headers.at("content-type").starts_with("text/event-stream")) {
				event_stream_ = true;
				return;
			}
		}
		if (100 <= status && status <= 199 || status == 204 || status == 304) {
			return; // no response body for 1XX, 204, 304
		}
		if (response_headers.contains("transfer-encoding")) {
			if (const auto& transfer_encoding = response_headers.at("transfer-encoding"); transfer_encoding.contains("chunked")) {
				while (true) {
					auto&& chunk_header = client.read_until('\n');
					if (!chunk_header.ends_with("\r\n"))
						throw http_response_parse_error();
					const auto semicolon = std::find(chunk_header.begin(), chunk_header.end() - 2, ';');
					int chunk_length;
					try {
						chunk_length = std::stoi(std::string{chunk_header.begin(), semicolon}, nullptr, 16);
					} catch (const std::exception&) {
						throw http_response_parse_error();
					}
					if (chunk_length == 0)
						break;
					auto chunk = client.read(chunk_length);
					auto chunk_end = client.read(2);
					if (chunk_end != "\r\n")
						throw http_response_parse_error();
					body += chunk;
				}
			}
		} else if (response_headers.contains("content-length")) {
			try {
				const auto length = std::stoull(response_headers.at("content-length"));
				body = client.read(length);
			} catch (const std::exception&) {
				throw http_response_parse_error();
			}
		} else {
			body = client.read_all();
		}
	}

}

#include "http1_1/client.h"
#include <list>
#include <algorithm>
#include <ranges>
#include <iostream>

namespace leaf::network::http {

	constexpr std::string safe_methods[] {"GET", "HEAD", "OPTIONS", "TRACE"}, idempotent_methods[] {"PUT", "DELETE"};
	constexpr auto ill_form_status_line = "ill-formed http status line";
	constexpr auto literal_location = "location";
	constexpr auto literal_transfer_encoding = "transfer-encoding";
	constexpr auto literal_content_length = "content-length";
	constexpr auto literal_chunked = "chunked";

	void client::connect_(const std::string_view host, const tcp_port_t port) {
		if (underlying_.connected() && connected_host_ == host && connected_port_ == port)
			return;
		underlying_.close();
		if (!underlying_.connect(host, port))
			throw std::runtime_error("connection failed");
		connected_host_ = host;
		connected_port_ = port;
	}

	response client::fetch(request _req) try {
		for (std::size_t redirection_count = 0; redirection_count < 7; ++redirection_count) {
			auto __p = _req.target.port;
			if (!__p) {
				if (_req.target.scheme == "http")
					__p = 80;
				else if (_req.target.scheme == "https")
					__p = 443;
				else
					throw std::invalid_argument("unknown scheme or set port explicitly");
			}
			connect_(_req.target.host, __p);
			auto copy = _req.headers;
			copy.set("host", _req.target.host);
			if (!_req.content.empty())
				copy.set("content-length", std::to_string(_req.content.length()));
			const auto req_str
					= std::format("{} {} HTTP/1.1\r\n{}\r\n{}", _req.method, _req.target.requesting_uri_string(),
								static_cast<std::string>(copy), _req.content);
			underlying_.write(reinterpret_cast<const byte_string&>(req_str));
			auto status_line = underlying_.read_line();
			if (!status_line.starts_with("HTTP/") || !status_line.ends_with('\r') || underlying_.read() != '\n')
				throw std::runtime_error(ill_form_status_line);
			auto it = std::next(status_line.begin(), 5);
			const auto version_it = std::find(it, status_line.end(), ' ');
			if (version_it == status_line.end())
				throw std::runtime_error(ill_form_status_line);
			const auto code_it = std::find(std::next(version_it), status_line.end(), ' ');
			if (code_it == status_line.end())
				throw std::runtime_error(ill_form_status_line);
			response res;
			try {
				auto ptr = code_it.base();
				res.status = std::strtoul(std::next(version_it).base(), &ptr, 10);
			} catch (const std::invalid_argument&) {
				throw std::runtime_error(ill_form_status_line);
			}
			res.headers = http_fields::from_http_headers(underlying_);
			if (100 <= res.status && res.status <= 199 || res.status == 204 || res.status == 304)
				// no response body for 1XX, 204, 304
				return res;
			if (res.headers.contains(literal_transfer_encoding)) {
				if (res.headers.at(literal_transfer_encoding).contains(literal_chunked)) {
					while (true) {
						auto chunk_head = underlying_.read_line();
						if (!chunk_head.ends_with('\r') || underlying_.read() != '\n')
							throw std::runtime_error("ill-formed chuck header");
						auto colon = std::find(chunk_head.begin(), chunk_head.end() - 1, ';').base();
						std::size_t chunk_len;
						try {
							chunk_len = std::strtoull(chunk_head.begin().base(), &colon, 16);
						} catch (const std::invalid_argument&) {
							throw std::runtime_error("ill-formed chunk length");
						}
						if (chunk_len == 0)
							break;
						const auto chunk_data = underlying_.read(chunk_len);
						res.content.append(chunk_data.begin(), chunk_data.end());
						if (underlying_.read(2) != reinterpret_cast<const std::uint8_t*>("\r\n"))
							throw std::runtime_error("ill-formed chunk data");
					}
				} else {
					// other transfer encodings are not implemented
					const auto content = underlying_.read_all();
					res.content = reinterpret_cast<const std::string&>(content);
				}
			} else if (res.headers.contains(literal_content_length)) {
				std::size_t content_length;
				try {
					content_length = std::stoull(res.headers.at(literal_content_length));
				} catch (const std::invalid_argument&) {
					throw std::runtime_error("ill-formed Content-Length");
				}
				const auto content = underlying_.read(content_length);
				res.content = reinterpret_cast<const std::string&>(content);
			} else {
				const auto content = underlying_.read_all();
				res.content = reinterpret_cast<const std::string&>(content);
			}
			if (!res.is_redirection() || !res.headers.contains(literal_location))
				return res;
			_req.target.replace(res.headers.at(literal_location));
		}
		return {};
	} catch (const std::exception& e) {
		std::cerr << std::format("exception thrown while fetching: {}\n", e.what());
		return {};
	}
}

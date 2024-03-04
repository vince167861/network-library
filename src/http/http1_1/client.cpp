#include "http1_1/client.h"
#include "http1_1/common.h"
#include <ranges>
#include <iostream>

namespace network::http {

	constexpr std::string_view safe_methods[] {"GET", "HEAD", "OPTIONS", "TRACE"}, idempotent_methods[] {"PUT", "DELETE"};
	constexpr auto literal_location = "location";

	void client::connect_(const std::string_view host, const tcp_port_t port) {
		if (base_.connected() && connected_host_ == host && connected_port_ == port)
			return;
		base_.close();
		base_.connect(host, port);
		connected_host_ = host;
		connected_port_ = port;
	}

	response client::fetch(request _req) try {
		for (std::size_t redirection_count = 0; redirection_count < 7; ++redirection_count) {
			const auto __p = [&] -> tcp_port_t {
				if (_req.target.port)
					return _req.target.port;
				if (_req.target.scheme == "http")
					return 80;
				if (_req.target.scheme == "https")
					return 443;
				throw std::invalid_argument("unknown scheme or set port explicitly");
			}();
			connect_(_req.target.host, __p);
			auto copy = _req.headers;
			copy.set("host", _req.target.host);
			if (!_req.content.empty())
				copy.set("content-length", std::to_string(_req.content.length()));
			const auto req_str
					= std::format("{} {} HTTP/1.1\r\n{}\r\n{}", _req.method, _req.target.origin_form(),
								static_cast<std::string>(copy), _req.content);
			base_.write(reinterpret_cast<const byte_string&>(req_str));
			const auto stat_l = base_.read_line();
			if (!stat_l.ends_with('\r') || base_.read() != '\n')
				throw client_error("fetch(request): status-line: invalid line folding");
			if (!stat_l.starts_with("HTTP/"))
				throw client_error("fetch(request): invalid HTTP response");
			const auto ws1 = stat_l.find(' ', 5);
			if (ws1 == std::string::npos)
				throw client_error("fetch(request): invalid HTTP response");
			const auto ws2 = stat_l.find(' ', ws1 + 1);
			if (ws2 == std::string::npos)
				throw client_error("fetch(request): invalid HTTP response");
			response res;
			const auto stat_code = stat_l.substr(ws1 + 1, ws2 - ws1 - 1);
			const auto begin = stat_code.data(), end = begin + stat_code.size();
			if (std::from_chars(begin, end, reinterpret_cast<std::uint16_t&>(res.code)).ec != std::errc{})
				throw client_error("fetch(request): ill-formed status code");
			res.headers = fields::from_http_headers(base_).value();
			if (informational(res.code) || res.code == status::no_content || res.code == status::not_modified)
				// no response body for 1XX, 204, 304
				return res;
			res.content = read_message_content(base_, res.headers, message_type::response).value();
			if (!redirection(res.code) || !res.headers.contains(literal_location))
				return res;
			_req.target = _req.target.from_relative(res.headers.at(literal_location));
		}
		return {};
	} catch (const std::exception& e) {
		std::cerr << std::format("exception thrown while fetching: {}\n", e.what());
		return {};
	}
}

#include "http1_1/server.h"
#include "http1_1/common.h"

namespace network::http {

	void server::listen(const tcp_port_t __p, const std::size_t max_connection) {
		base_.listen(__p, max_connection);
	}

	std::unique_ptr<serverside_endpoint> server::accept() {
		return std::make_unique<serverside_endpoint>(base_.accept());
	}

	std::expected<request, request_parse_error> serverside_endpoint::fetch() {
		const auto req_l = base_->read_line();
		if (req_l.back() != '\r' || base_->read() != '\n') {
			send_error_(request_parse_error::invalid_line_folding);
			return std::unexpected{request_parse_error::invalid_line_folding};
		}
		const auto ws1 = req_l.find(' ');
		if (ws1 == std::string::npos) {
			send_error_(request_parse_error::request_line_missing_space);
			return std::unexpected{request_parse_error::request_line_missing_space};
		}
		const auto ws2 = req_l.find(' ', ws1 + 1);
		if (ws2 == std::string::npos) {
			send_error_(request_parse_error::request_line_missing_space);
			return std::unexpected{request_parse_error::request_line_missing_space};
		}
		request __r;
		__r.method = req_l.substr(0, ws1);
		try {
			__r.target = uri::from(req_l.substr(ws1 + 1, ws2 - ws1 - 1));
		} catch (...) {
			send_error_(request_parse_error::invalid_request_target);
			return std::unexpected{request_parse_error::invalid_request_target};
		}
		auto field_r = fields::from_http_headers(*base_);
		if (!field_r) {
			send_error_(request_parse_error::invalid_header_fields);
			return std::unexpected{request_parse_error::invalid_header_fields};
		}
		__r.headers = std::move(field_r.value());
		auto content_r = read_message_content(*base_, __r.headers, message_type::request);
		if (!content_r) {
			send_error_(request_parse_error::message_content_error);
			return std::unexpected{request_parse_error::message_content_error};
		}
		__r.content = std::move(content_r.value());
		return __r;
	}

	void serverside_endpoint::send(const response& __r) {
		const auto res = std::format(
			"HTTP/1.1 {} \r\n{}\r\n{}",
			static_cast<std::uint16_t>(__r.code), static_cast<std::string>(__r.headers), __r.content);
		base_->write(reinterpret_cast<const byte_string&>(res));
	}

	void serverside_endpoint::send_error_(const request_parse_error error) {
		switch (error) {
			case request_parse_error::invalid_line_folding:
				send_as_html_(status::bad_request, "invalid line folding in request message");
				break;
			case request_parse_error::request_line_missing_space:
				send_as_html_(status::bad_request, "missing fields in request line");
				break;
			case request_parse_error::invalid_request_target:
				send_as_html_(status::bad_request, "invalid request URL");
				break;
			case request_parse_error::invalid_header_fields:
				send_as_html_(status::bad_request, "invalid request headers");
				break;
			default:
				send_as_html_(status::internal_error, "server internal error");
				throw std::runtime_error("unimplemented");
		}
	}

	void serverside_endpoint::send_as_html_(const status code, const std::string_view text) {
		send({
			{{{"content-type", "text/html"}}},
			code,
			std::format("<html><body><p>{}</p></body></html>", text)});
	}
}

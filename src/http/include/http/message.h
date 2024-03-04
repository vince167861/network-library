#pragma once
#include <expected>

#include "basic_stream.h"
#include "http/uri.h"
#include <map>
#include <format>

namespace network::http {

	namespace internal {

		struct field_name_less {

			bool operator()(const std::string&, const std::string&) const;
		};

		using field_base = std::map<std::string, std::string, field_name_less>;
	}

	enum class field_parse_error {
		invalid_line_folding, obsolete_line_folding, missing_colon, invalid_whitespace_after_name
	};

	struct fields: internal::field_base {

		using internal::field_base::map;

		std::string& append(std::string_view name, std::string_view value, std::string_view sep = ",");

		std::string& set(std::string_view name, std::string_view value);

		void remove(std::string_view name);

		operator std::string() const;

		static std::expected<fields, field_parse_error> from_http_headers(istream&);

		static fields from_event_stream(istream&);
	};

	enum class message_type {
		request, response
	};


	enum class status: std::uint16_t {
		no_content = 204, not_modified = 304, bad_request = 400, internal_error = 500
	};

	inline bool informational(const status code) {
		return static_cast<std::uint16_t>(code) / 100 == 1;
	}

	inline bool redirection(const status code) {
		return static_cast<std::uint16_t>(code) / 100 == 3;
	}


	struct message {

		fields headers;
	};


	struct request final: message {

		std::string method;

		uri target;

		std::string content;

		request() = default;

		request(std::string method, uri, fields headers = {});

		bool operator==(const request&) const;
	};


	struct response final: message {

		status code;

		std::string content;
	};


	struct event {

		std::string event_type;

		std::string data;

		std::optional<std::string> id;
	};


	struct client_error final: std::runtime_error {

		explicit client_error(const std::string_view msg)
			: std::runtime_error(std::format("[HTTP client] {}", msg)) {
		}
	};


	struct error final: std::runtime_error {

		const status code;

		explicit error(const status code, const std::string_view msg)
			: std::runtime_error(std::format("[HTTP] {}", msg)), code(code) {
		}
	};
}


template<>
struct std::hash<network::http::request> {

	std::size_t operator()(const network::http::request&) const;
};


template<>
struct std::formatter<network::http::request> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const network::http::request& req, std::format_context& ctx) const {
		return std::format_to(ctx.out(),
			"request {} {}\n{}\n{}",
			req.method, req.target.to_absolute(), static_cast<std::string>(req.headers), req.content);
	}
};


template<>
struct std::formatter<network::http::response> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const network::http::response& response, std::format_context& ctx) const {
		return std::format_to(ctx.out(),
			"response ({})\n{}\n{}",
			static_cast<std::uint16_t>(response.code), static_cast<std::string>(response.headers), response.content);
	}
};

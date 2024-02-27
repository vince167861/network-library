#pragma once
#include "basic_endpoint.h"
#include "http/url.h"
#include <functional>
#include <map>
#include <format>

namespace leaf::network::http {

	namespace internal {

		struct http_field_name_less {

			bool operator()(const std::string&, const std::string&) const;
		};

		using http_field_base = std::map<std::string, std::string, http_field_name_less>;
	}


	struct http_fields: internal::http_field_base {

		using internal::http_field_base::map;

		std::string& append(std::string_view name, std::string_view value, std::string_view sep = ",");

		std::string& set(std::string_view name, std::string_view value);

		void remove(std::string_view name);

		operator std::string() const;

		static http_fields from_http_headers(istream&);

		static http_fields from_event_stream(istream&);
	};


	struct message {

		http_fields headers;
	};


	struct request final: message {

		std::string method;

		url target;

		std::string content;

		request() = default;

		request(std::string method, url, http_fields headers = {});

		bool operator==(const request&) const;
	};


	struct response final: message {

		unsigned status;

		std::string content;

		bool is_redirection() const {
			return 300 <= status && status <= 399;
		}
	};


	struct event {

		std::string event_type;

		std::string data;

		std::optional<std::string> id;
	};
}

template<>
struct std::hash<leaf::network::http::request> {

	std::size_t operator()(const leaf::network::http::request&) const;
};


template<>
struct std::formatter<leaf::network::http::request> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::network::http::request& req, std::format_context& ctx) const {
		return std::format_to(ctx.out(), "request {} {}\n{}\n{}", req.method, req.target.url_string(), static_cast<std::string>(req.headers), req.content);
	}
};


template<>
struct std::formatter<leaf::network::http::response> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::network::http::response& response, std::format_context& ctx) const {
		return std::format_to(ctx.out(), "response ({})\n{}\n{}", response.status, static_cast<std::string>(response.headers), response.content);
	}
};

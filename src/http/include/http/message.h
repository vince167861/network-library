#pragma once
#include "basic_endpoint.h"
#include "url.h"
#include <map>
#include <string>
#include <format>

namespace leaf::network::http {

	struct http_field_name_less {

		constexpr bool operator()(const std::string&, const std::string&) const;
	};


	struct http_fields: std::map<std::string, std::string, http_field_name_less> {

		using std::map<std::string, std::string, http_field_name_less>::map;

		std::string& append(std::string_view name, std::string_view value, std::string_view sep = ",");

		std::string& set(std::string_view name, std::string_view value);

		void remove(std::string_view name);

		operator std::string();

		static http_fields from_http_headers(istream&);

		static http_fields from_event_stream(istream&);
	};


	struct message {

		http_fields headers;
	};


	struct request final: message {

		std::string method;

		url request_url;

		std::string body;

		request() = default;

		request(std::string method, url, http_fields headers = {});

		void print(std::ostream&) const;
	};


	struct response final: message {

		long status;

		std::string body;

		bool is_redirection() const;
	};
}


template<>
struct std::formatter<leaf::network::http::response> {

	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}

	auto format(const leaf::network::http::response& response, std::format_context& ctx) const {
		return std::format_to(ctx.out(), "response (status {})\n{}", response.status, response.body);
	}
};

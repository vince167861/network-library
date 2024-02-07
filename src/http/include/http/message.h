#pragma once
#include "basic_client.h"
#include <map>

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

		static http_fields from_http_headers(stream& source);

		static http_fields from_event_stream(stream& source);
	};


	struct message {
		http_fields headers;
	};
}

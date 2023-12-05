#pragma once

#include "shared/client.h"

#include <map>
#include <string>

namespace leaf::network {

	std::map<std::string, std::string> parse_http_fields(client&);

	std::map<std::string, std::string> from_url_encoded(std::string_view);

	std::string to_url_encoded(const std::map<std::string, std::string>&);

	class url {
	public:
		std::string scheme;

		std::string username;

		[[deprecated("Sending password in URL is not secure.")]]
		std::string password;

		std::string host;

		uint16_t port = 0;

		std::string path;

		std::map<std::string, std::string> query;

		std::string fragment;

		url() = default;

		url(std::string_view); // NOLINT(*-explicit-constructor)

		static std::string to_percent_encoding(const std::string& string);

		static std::string from_percent_encoding(std::string_view);
	};


	class invalid_url final: public std::exception {
	};
} // leaf

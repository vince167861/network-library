#pragma once

#include "shared/client.h"

#include <list>
#include <string>

namespace leaf::network {

	std::list<std::pair<std::string, std::string>>
	from_url_encoded(std::string_view);

	std::string
	to_url_encoded(const std::list<std::pair<std::string, std::string>>&);

	std::string from_percent_encoding(std::string_view);

	std::string to_percent_encoding(std::string_view);

	class url {
	public:
		std::string scheme;

		std::string username;

		[[deprecated("Sending password in URL is not secure.")]]
		std::string password;

		std::string host;

		uint16_t port = 0;

		std::string path;

		std::list<std::pair<std::string, std::string>> query;

		std::string fragment;

		url() = default;

		url(std::string_view);

		std::string url_string() const;

		std::string uri_string() const;

		std::string requesting_uri_string() const;
	};


	class invalid_url final: public std::exception {
	};
} // leaf

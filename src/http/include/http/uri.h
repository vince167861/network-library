#pragma once
#include <cstdint>
#include <list>
#include <string>

namespace leaf::network {

	struct uri {

		std::string scheme, userinfo, host;

		std::uint16_t port = 0;

		std::string path, query, fragment;

		uri() = default;

		uri(std::string_view);

		void normalize();

		uri from_relative(const uri&) const;

		std::string to_absolute() const;

		std::string to_relative() const;

		std::string origin_form() const;

		bool operator==(const uri&) const;
	};

	std::list<std::pair<std::string, std::string>>
	from_url_encoded(std::string_view);

	std::string
	to_url_encoded(const std::list<std::pair<std::string, std::string>>&);

	std::string from_pct_encoding(std::string_view);

	std::string to_percent_encoding(std::string_view);
}

template<>
struct std::hash<leaf::network::uri> {

	std::size_t operator()(const leaf::network::uri&) const;
};

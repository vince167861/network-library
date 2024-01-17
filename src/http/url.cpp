#include "http/url.h"

#include "utils.h"
#include <format>

namespace leaf::network {

	std::runtime_error invalid_url{"url provided is invalid."};

	std::string
	to_url_encoded(const std::list<std::pair<std::string, std::string>>& values) {
		std::string str;
		for (bool first = true; auto& [key, value]: values) {
			str += std::format("{}{}={}",
				first ? (first = false, "") : "&", to_percent_encoding(key), to_percent_encoding(value));
		}
		return str;
	}

	std::list<std::pair<std::string, std::string>>
	from_url_encoded(std::string_view source) {
		std::list<std::pair<std::string, std::string>> pair;
		while (!source.empty()) {
			auto eq = std::ranges::find(source, '=');
			auto amp = std::ranges::find(source, '&');
			if (eq < amp)
				pair.emplace_back(
					from_percent_encoding({source.begin(), eq}),
					from_percent_encoding({eq + 1, amp}));
			else
				pair.emplace_back(from_percent_encoding({source.begin(), amp}), "");
			if (amp == source.end())
				break;
			source = {amp + 1, source.end()};
		}
		return pair;
	}

	url::url(std::string_view string) {
		const auto scheme_end = std::ranges::find(string, ':');
		if (scheme_end == string.end())
			throw invalid_url;
		scheme = {string.begin(), scheme_end};
		for (std::size_t i = 0; i < scheme.size(); ++i) {
			auto& c = scheme[i];
			if ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z')
				continue;
			if (i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'))
				continue;
			throw invalid_url;
		}
		auto authority_end = scheme_end + 1;
		if (*authority_end == '/' && *(authority_end + 1) == '/') {
			// contains authority
			authority_end = std::ranges::find_first_of(std::string_view{authority_end + 2, string.end()}, "/?#");
			auto at = std::find(scheme_end + 3, authority_end, '@');
			if (at != authority_end) {
				// contains userinfo
				if (const auto colon = std::find(scheme_end + 3, at, ':'); colon != at) {
					// contains password
					this->username = {scheme_end + 3, colon};
					this->password = {colon + 1, at};
				} else
					this->username = {scheme_end + 3, at};
			} else
				at = scheme_end + 3;
			if (const auto colon = std::find(at, authority_end, ':'); colon != authority_end) {
				// contains port
				host = {at, colon};
				std::string port_string{colon + 1, authority_end};
				if (!port_string.empty())
					this->port = std::stoi(port_string);
			} else
				host = {at, authority_end};
		}
		const auto path_end = std::ranges::find_first_of(std::string_view{authority_end, string.end()}, "?#");
		path = {authority_end, path_end};
		auto query_ends = path_end;
		if (path_end != string.end() && *path_end == '?') {
			// contains query
			query_ends = std::find(path_end + 1, string.end(), '#');
			query = from_url_encoded({path_end + 1, query_ends});
		}
		if (query_ends != string.end() && *query_ends == '#')
			// contains fragment
			fragment = {query_ends + 1, string.end()};
	}

	std::string url::url_string() const {
		auto str = scheme + ':';
		if (!host.empty()) {
			str += "//";
			if (!username.empty())
				str += std::format("{}{}@", username, password.empty() ? "" : ':' + password);
			str += host;
			if (port)
				str += ':' + port;
		}
		str += uri_string();
		return str;
	}

	std::string url::uri_string() const {
		auto uri = path;
		if (!query.empty())
			uri += "?" + to_url_encoded(query);
		if (!fragment.empty())
			uri += "#" + fragment;
		return uri;
	}

	std::string url::requesting_uri_string() const {
		auto uri = path.empty() ? "/" : path;
		if (!query.empty())
			uri += "?" + to_url_encoded(query);
		return uri;
	}

	void url::replace(std::string_view uri) {
		auto scheme_end = std::ranges::find(uri, ':');
		if (scheme_end != uri.end()) {
			scheme = {uri.begin(), scheme_end};
			for (std::size_t i = 0; i < scheme.size(); ++i) {
				auto& c = scheme[i];
				if ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z')
					continue;
				if (i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'))
					continue;
				throw invalid_url;
			}
		} else
			std::advance(scheme_end, -1);
		auto authority_end = std::next(scheme_end, 1);
		if (std::equal(authority_end, std::next(authority_end, 2), "//")) {
			authority_end = std::ranges::find_first_of(std::string_view{authority_end + 2, uri.end()}, "/?#");
			auto at = std::find(scheme_end + 3, authority_end, '@');
			if (at != authority_end) {
				if (const auto colon = std::find(scheme_end + 3, at, ':'); colon != at) {
					this->username = {scheme_end + 3, colon};
					this->password = {colon + 1, at};
				} else
					this->username = {scheme_end + 3, at};
			} else
				at = scheme_end + 3;
			if (const auto colon = std::find(at, authority_end, ':'); colon != authority_end) {
				host = {at, colon};
				std::string port_string{colon + 1, authority_end};
				if (!port_string.empty())
					this->port = std::stoi(port_string);
			} else
				host = {at, authority_end};
		}
		const auto path_end = std::ranges::find_first_of(std::string_view{authority_end, uri.end()}, "?#");
		path = {authority_end, path_end};
		auto query_ends = path_end;
		if (path_end != uri.end() && *path_end == '?') {
			query_ends = std::find(path_end + 1, uri.end(), '#');
			query = from_url_encoded({path_end + 1, query_ends});
		}
		if (query_ends != uri.end() && *query_ends == '#')
			fragment = {query_ends + 1, uri.end()};
	}

	std::string to_percent_encoding(const std::string_view string) {
		std::string str;
		for (auto c: string) {
			switch (c) {
				case ':':case '/':case '?':case '#':case '[':
				case ']':case '@':case '!':case '$':case '&':
				case '\'':case '(':case ')':case '*':case '+':
				case ',':case ';':case '=':
					str += std::format("%{:02X}", c);
					break;
				default:
					str.push_back(c);
			}
		}
		return str;
	}

	std::string from_percent_encoding(const std::string_view string) {
		std::string result;
		result.reserve(string.length());
		for (auto ptr = string.begin(); ptr != string.end(); ++ptr) {
			if (*ptr == '%') {
				std::string number{ptr + 1, ptr + 3};
				result.push_back(static_cast<char>(std::stoi(number, nullptr, 16)));
				ptr += 2;
			} else
				result += *ptr;
		}
		return result;
	}
}

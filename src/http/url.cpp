#include "http/url.h"
#include "http/http_exception.h"

#include "utils.h"
#include <sstream>
#include <iomanip>

namespace leaf::network {

	std::map<std::string, std::string>
	parse_http_fields(client& data) {
		std::map<std::string, std::string> pair;
		while (true) {
			auto&& line = data.read_until('\n');
			if (!line.ends_with("\r\n"))
				throw http_field_parse_error();
			if (line.length() == 2)		// only contains "\r\n"; end of fields
				break;
			auto colon = std::ranges::find(line, ':');
			if (colon == line.end())
				throw http_field_parse_error();
			pair.emplace(to_lower({(line.begin()), colon}), trim({colon + 1, line.end()}));
		}
		return pair;
	}

	std::string
	to_url_encoded(const std::map<std::string, std::string>& values) {
		bool first = true;
		std::stringstream ret;
		for (auto& [key, value]: values) {
			if (first)
				ret << '&', first = false;
			ret << url::to_percent_encoding(key) << '=' << url::to_percent_encoding(value);
		}
		return ret.str();
	}

	std::map<std::string, std::string>
	from_url_encoded(std::string_view source) {
		std::map<std::string, std::string> pair;
		while (!source.empty()) {
			auto eq = std::ranges::find(source, '=');
			auto amp = std::ranges::find(source, '&');
			if (eq < amp)
				pair.emplace(url::from_percent_encoding({source.begin(), eq}), url::from_percent_encoding({eq + 1, amp}));
			else
				pair.emplace(url::from_percent_encoding({source.begin(), amp}), "");
			if (amp == source.end())
				break;
			source = {amp + 1, source.end()};
		}
		return pair;
	}

	url::url(std::string_view string) {
		const auto scheme_end = std::ranges::find(string, ':');
		if (scheme_end == string.end())
			throw invalid_url{};
		scheme = {string.begin(), scheme_end};
		for (std::size_t i = 0; i < scheme.size(); ++i) {
			auto& c = scheme[i];
			if ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z')
				continue;
			if (i > 0 && ('0' <= c && c <= '9' || c == '+' || c == '-' || c == '.'))
				continue;
			throw invalid_url{};
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

	std::string
	url::to_percent_encoding(const std::string& string) {
		std::stringstream result;
		for (auto c: string) {
			switch (c) {
				case ':':case '/':case '?':case '#':case '[':
				case ']':case '@':case '!':case '$':case '&':
				case '\'':case '(':case ')':case '*':case '+':
				case ',':case ';':case '=':
					result << '%' << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << c;
					break;
				default:
					result << c;
			}
		}
		return result.str();
	}

	std::string
	url::from_percent_encoding(const std::string_view string) {
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

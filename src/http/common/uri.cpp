#include "http/uri.h"
#include "internal/utils.h"
#include "stl_hash.h"
#include <format>
#include <charconv>
#include <utility>

using namespace internal;

namespace network {

	std::string from_pct_encoding(const std::string_view __i) {
		std::string __r;
		__r.reserve(__i.length());
		const auto end = __i.end();
		for (auto it = __i.begin(); it != end; ++it) {
			if (*it == '%') {
				char c;
				if (std::from_chars(it + 1, it + 3, c, 16).ptr != it + 3)
					throw std::runtime_error("invalid percent encoding");
				__r.push_back(c);
				std::advance(it, 2);
			} else
				__r.push_back(*it);
		}
		return __r;
	}

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
					from_pct_encoding({source.begin(), eq}),
					from_pct_encoding({eq + 1, amp}));
			else
				pair.emplace_back(from_pct_encoding({source.begin(), amp}), "");
			if (amp == source.end())
				break;
			source = {amp + 1, source.end()};
		}
		return pair;
	}

	bool pct_encoded(auto& it) {
		bool __r = *it == '%' && std::isxdigit(*(it + 1)) && std::isxdigit(*(it + 2));
		if (__r)
			it += 2;
		return __r;
	}

	std::optional<std::string> parse_scheme(auto& begin, const auto end) {
		bool valid = true;
		for (auto it = begin; it != end; ++it) {
			if (*it == ':') {
				if (!valid)
					throw std::invalid_argument("scheme accepts only /[A-Za-z][A-Za-z0-9+-.]*/");
				auto __r = to_lower({begin, it});
				begin = it + 1;
				return __r;
			}
			const auto c = *it;
			if (std::isalpha(c))
				continue;
			if (it != begin && (std::isdigit(c) || c == '+' || c == '-' || c == '.'))
				continue;
			valid = false;
		}
		return std::nullopt;
	}

	constexpr std::string_view unreserved("-_.~"), subdelims("!$&'()*+,;=");

	std::string parse_userinfo(auto& begin, const auto end) {
		bool valid = true;
		for (auto it = begin; it != end; ++it) {
			const auto c = *it;
			if (c == '@') {
				if (!valid)
					throw std::invalid_argument("userinfo accepts only /(?:[A-Za-z0-9-_.~!$&'()*+,;=]|%[A-Za-z0-9]{2})*/");
				std::string __r(begin, it);
				begin = it + 1;
				return __r;
			}
			if (std::isalnum(c) || unreserved.contains(c) || subdelims.contains(c) || c == ':' || pct_encoded(it))
				continue;
			valid = false;
		}
		return {};
	}

	constexpr std::string_view authority_end("/?#"), path_end("?#");

	std::string parse_host(auto& begin, const auto end) {
		constexpr std::string_view host_end("/?#:");
		auto it = begin;
		for (; it != end; ++it) {
			const auto c = *it;
			if (host_end.contains(c))
				break;
			if (std::isalnum(c) || unreserved.contains(c) || subdelims.contains(c) || pct_encoded(it))
				continue;
			throw std::invalid_argument(std::format("invalid character '{0}' ({0:#x}) in \"host\"", c));
		}
		std::string __r(begin, it);
		begin = it;
		return __r;
	}

	std::uint16_t parse_port(auto& __b, const auto __e) {
		if (*__b != ':')
			return {};
		auto it = ++__b;
		for (; it != __e; ++it) {
			const auto c = *it;
			if (authority_end.contains(c))
				break;
			if (!std::isdigit(c))
				throw std::invalid_argument("port accepts only [0-9]*");
		}
		std::uint16_t __r;
		const auto parse_r = std::from_chars(__b, it, __r);
		__b = it;
		if (parse_r.ec == std::errc())
			return __r;
		throw std::runtime_error("port parse error");
	}

	std::optional<std::tuple<std::string, std::string, std::uint16_t>>
	parse_authority(auto& __begin, const auto __end) {
		if (*__begin != '/' || *(__begin + 1) != '/')
			return std::nullopt;
		std::advance(__begin, 2);
		auto userinfo = from_pct_encoding(parse_userinfo(__begin, __end));
		auto host = from_pct_encoding(parse_host(__begin, __end));
		auto port = parse_port(__begin, __end);
		return {{std::move(userinfo), std::move(host), port}};
	}

	bool path_char(auto& it) {
		return std::isalnum(*it) || unreserved.contains(*it) || subdelims.contains(*it) || *it == ':' || *it == '@' || pct_encoded(it);
	}

	std::string remove_dot_segments(std::string_view path) {
		std::string __r;
		while (!path.empty()) {
			if (path.starts_with("../"))
				path.remove_prefix(3);
			else if (path.starts_with("./") || path.starts_with("/./"))
				path.remove_prefix(2);
			else if (path.starts_with("/../")) {
				if (const auto pos = __r.find_last_of('/'); pos == std::string::npos)
					__r.clear();
				else
					__r.erase(pos);
 				path.remove_prefix(3);
			} else if (path == "/..") {
				__r.erase(__r.find_last_of('/') + 1);
				break;
			} else if (path == "." || path == "..")
				path = {};
			else if (path == "/.") {
				path = {};
				__r.push_back('/');
			} else {
				const auto pos = path.find_first_of('/', 1);
				__r.append(path, 0, pos);
				if (pos == std::string_view::npos)
					break;
				path.remove_prefix(pos);
			}
		}
		return __r;
	}

	std::string_view parse_path(auto& __begin, const auto __end) {
		if (__begin == __end)
			return {};
		auto it = __begin;
		for (; it != __end; ++it) {
			const auto c = *it;
			if (path_end.contains(c))
				break;
			if (c == '/' || path_char(it))
				continue;
			throw std::invalid_argument("invalid charater in path component");
		}
		const auto begin = std::exchange(__begin, it);
		return {begin, it};
	}

	std::optional<std::string_view> parse_query(auto& __begin, const auto end) {
		if (*__begin != '?')
			return std::nullopt;
		auto it = __begin + 1;
		for (; it != end; ++it) {
			const auto c = *it;
			if (c == '#')
				break;
			if (c == '/' || c == '?' || path_char(it))
				continue;
			throw std::invalid_argument("invalid charater in query component");
		}
		const auto begin = std::exchange(__begin, it) + 1;
		return {{begin, it}};
	}

	std::string_view parse_fragment(auto& __begin, const auto __end) {
		if (*__begin != '#')
			return {};
		for (auto it = __begin + 1; it != __end; ++it) {
			const auto c = *it;
			if (c == '/' || c == '?' || path_char(it))
				continue;
			throw std::invalid_argument("invalid charater in fragment component");
		}
		const auto begin = std::exchange(__begin, __end) + 1;
		return {begin, __end};
	}

	uri uri::from(const std::string_view __s) {
		uri __r;
		auto it = __s.begin();
		const auto end = __s.end();
		__r.scheme = parse_scheme(it, end).value_or("");
		if (auto authority = parse_authority(it, end))
			std::tie(__r.userinfo, __r.host, __r.port) = std::move(authority.value());
		__r.path = remove_dot_segments(parse_path(it, end));
		__r.query = parse_query(it, end).value_or("");
		__r.fragment = parse_fragment(it, end);
		return __r;
	}

	std::string uri::to_absolute() const {
		std::string __r;
		if (!scheme.empty()) {
			__r += scheme;
			__r += ':';
		}
		if (!host.empty()) {
			__r += "//";
			if (!userinfo.empty())
				__r += std::format("{}@", userinfo);
			__r += host;
			if (port) {
				__r += ':';
				__r += std::to_string(port);
			}
		}
		__r += to_relative();
		return __r;
	}

	std::string uri::to_relative() const {
		auto uri = path;
		if (!query.empty())
			uri += "?" + query;
		if (!fragment.empty())
			uri += "#" + fragment;
		return uri;
	}

	std::string uri::origin_form() const {
		auto uri = path.empty() ? "/" : path;
		if (!query.empty())
			uri += "?" + query;
		return uri;
	}

	std::string merge_path(const std::string_view base, const std::string_view ref) {
		if (auto pos = base.find_last_of('/'); pos == std::string_view::npos)
			return std::string(ref);
		else {
			std::string __t(base.begin(), pos + 1);
			__t += ref;
			return __t;
		}
	}

	uri uri::from_relative(const std::string_view ref) const {
		uri __r;
		auto it = ref.begin();
		const auto end = ref.end();
		if (auto r_scheme = parse_scheme(it, end)) {
			__r.scheme = std::move(r_scheme.value());
			if (auto authority = parse_authority(it, end))
				std::tie(__r.userinfo, __r.host, __r.port) = std::move(authority.value());
			__r.path = remove_dot_segments(parse_path(it, end));
			__r.query = parse_query(it, end).value_or("");
		} else {
			if (auto authority = parse_authority(it, end)) {
				std::tie(__r.userinfo, __r.host, __r.port) = std::move(authority.value());
				__r.path = remove_dot_segments(parse_path(it, end));
				__r.query = parse_query(it, end).value_or("");
			} else {
				if (const auto ref_path = parse_path(it, end); ref_path.empty()) {
					__r.path = path;
					__r.query = parse_query(it, end).value_or(query);
				} else {
					__r.path = remove_dot_segments(ref_path.starts_with('/') ? ref_path : merge_path(path, ref_path));
					__r.query = parse_query(it, end).value_or("");
				}
				__r.userinfo = userinfo;
				__r.host = host;
				__r.port = port;
			}
			__r.scheme = scheme;
		}
		__r.fragment = parse_fragment(it, end);
		return __r;
	}

	bool uri::operator==(const uri& u) const {
		return scheme == u.scheme && userinfo == u.userinfo && host == u.host
			&& port == u.port && path == u.path && query == u.query && fragment == u.fragment;
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
}

std::size_t std::hash<network::uri>::operator()(const network::uri& u) const noexcept {
	std::size_t result;
	hash_combine(result, u.scheme);
	hash_combine(result, u.userinfo);
	hash_combine(result, u.host);
	hash_combine(result, u.port);
	hash_combine(result, u.path);
	hash_combine(result, u.query);
	hash_combine(result, u.fragment);
	return result;
}

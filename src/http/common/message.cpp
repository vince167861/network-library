#include "http/message.h"
#include "internal/utils.h"
#include "custom_std/hash.h"
#include <format>

using namespace internal;

constexpr std::string_view WS{" \t"};

namespace network::http {

	std::string& fields::append(const std::string_view name, const std::string_view value, const std::string_view sep) {
		auto lower_name = to_lower(name);
		if (!contains(lower_name))
			return set(name, value);
		auto& field = at(lower_name);
		field += sep;
		return field += value;
	}

	std::string& fields::set(const std::string_view name, const std::string_view value) {
		return operator[](to_lower(name)) = value;
	}

	fields::operator std::string() const {
		std::string str;
		for (auto& [field, value]: *this)
			str += std::format("{}: {}\r\n", field, value);
		return str;
	}

	bool internal::field_name_less::operator()(const std::string& lhs, const std::string& rhs) const {
		const auto result = lhs <=> rhs;
		return std::is_gt(result) && lhs == "host" || std::is_lt(result);
	}

	std::expected<fields, field_parse_error> fields::from_http_headers(istream& __s) {
		fields fields;
		for (;;) {
			const auto __fl = __s.read_line();
			if (!__fl.ends_with('\r') || __s.read() != '\n')
				return std::unexpected{field_parse_error::invalid_line_folding};
			if (__fl.length() == 1)
				// only contains CR; end of fields
				break;
			if (WS.contains(__fl.front()))
				return std::unexpected{field_parse_error::obsolete_line_folding};
			const auto __c = std::ranges::find(__fl, ':');
			if (__c == __fl.end())
				return std::unexpected{field_parse_error::missing_colon};
			if (WS.contains(*(__c - 1)))
				return std::unexpected{field_parse_error::invalid_whitespace_after_name};
			fields.append({__fl.begin(), __c}, trim({__c + 1, __fl.end()}));
		}
		return fields;
	}

	fields fields::from_event_stream(istream& __s) {
		fields fields;
		bool __end_cr = false;
		for (;;) {
			const auto __l = __s.read_line();
			if (__end_cr && __l == "\n") {
				__end_cr = false;
				continue;
			}
			__end_cr = __l.ends_with('\r');
			if (__l.length() == 1)
				// only contains terminator; end of fields
				break;
			const auto __c = std::ranges::find(__l, ':');
			fields.append({__l.begin(), __c}, ::internal::trim(__c == __l.end() ? "" : std::string_view{__c + 1, __l.end()}), "\n");
		}
		return fields;
	}

	request::request(std::string method, uri target, fields headers)
			: message{std::move(headers)}, method(std::move(method)), target(std::move(target)) {
	}

	bool request::operator==(const request& lhs) const {
		return method == lhs.method && target == lhs.target && content == lhs.content && headers == lhs.headers;
	}
}

std::size_t std::hash<network::http::request>::operator()(const network::http::request& req) const {
	std::size_t result = 0;
	hash_combine(result, reinterpret_cast<const network::http::internal::field_base&>(req.headers));
	hash_combine(result, req.method);
	hash_combine(result, req.target);
	hash_combine(result, req.content);
	return result;
}

#include "http/message.h"
#include "utils.h"

#include <format>

namespace leaf::network::http {

	const std::runtime_error http_field_parse_error{"invalid HTTP fields format"};


	std::string& http_fields::append(const std::string_view name, const std::string_view value, const std::string_view sep) {
		auto lower_name = to_lower(name);
		if (!contains(lower_name))
			return set(name, value);
		auto& field = at(lower_name);
		field += sep;
		return field += value;
	}

	std::string& http_fields::set(const std::string_view name, const std::string_view value) {
		return operator[](to_lower(name)) = value;
	}

	http_fields::operator std::string() {
		std::string str;
		for (auto& [field, value]: *this)
			str += std::format("{}: {}\r\n", field, value);
		return str;
	}

	bool http_field_name_less::operator()(const std::string& lhs, const std::string& rhs) const {
		const auto result = lhs <=> rhs;
		return std::is_gt(result) && lhs == "host" || std::is_lt(result);
	}

	http_fields http_fields::from_http_headers(istream& __s) {
		http_fields fields;
		for (;;) {
			const auto __fl = __s.read_line();
			if (!__fl.ends_with('\r') || __s.read() != '\n')
				throw http_field_parse_error;
			if (__fl.length() == 1)
				// only contains CR; end of fields
				break;
			const auto __c = std::ranges::find(__fl, ':');
			if (__c == __fl.end())
				throw http_field_parse_error;
			fields.append({__fl.begin(), __c}, trim({__c + 1, __fl.end()}));
		}
		return fields;
	}

	http_fields http_fields::from_event_stream(istream& __s) {
		http_fields fields;
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
			fields.append({__l.begin(), __c}, trim(__c == __l.end() ? "" : std::string_view{__c + 1, __l.end()}), "\n");
		}
		return fields;
	}

	request::request(std::string method, url target, http_fields headers)
			: message{std::move(headers)}, method(std::move(method)), request_url(std::move(target)) {
	}

	bool response::is_redirection() const {
		return 300 <= status && status <= 399;
	}
}

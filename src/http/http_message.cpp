#include "http/message.h"
#include "utils.h"

#include <format>

namespace leaf::network::http {

	const std::runtime_error http_field_parse_error{"invalid HTTP fields format"};


	std::string& http_fields::append(std::string_view name, std::string_view value, std::string_view sep) {
		auto lower_name = to_lower(name);
		if (!contains(lower_name))
			return set(name, value);
		auto& field = at(lower_name);
		field += sep;
		return field += value;
	}

	std::string& http_fields::set(std::string_view name, std::string_view value) {
		return operator[](to_lower(name)) = value;
	}

	http_fields::operator std::string() {
		std::string str;
		for (auto& [field, value]: *this)
			str += std::format("{}: {}\r\n", field, value);
		return str;
	}

	constexpr bool http_field_name_less::operator()(const std::string& lhs, const std::string& rhs) const {
		auto result = lhs <=> rhs;
		return std::is_gt(result) && lhs == "host" || std::is_lt(result);
	}
}

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

	http_fields http_fields::from_http_headers(stream& source) {
		http_fields fields;
		while (true) {
			auto line = source.read_until("\n");
			if (!line.ends_with("\r\n"))
				throw http_field_parse_error;
			if (line.length() == 2)		// only contains "\r\n"; end of fields
				break;
			auto colon = std::ranges::find(line, ':');
			if (colon == line.end())
				throw http_field_parse_error;
			fields.append({line.begin(), colon}, trim({colon + 1, line.end()}));
		}
		return fields;
	}

	http_fields http_fields::from_event_stream(stream& source) {
		http_fields fields;
		for (char last_terminator = '\n';;) {
			auto line = source.read_until("\r\n");
			if (last_terminator == '\r' && line.starts_with('\n'))
				line.erase(0, 1);
			last_terminator = line.back();
			if (line.length() == 1)		// only contains terminator; end of fields
				break;
			auto colon = std::ranges::find(line, ':');
			fields.append(
					{line.begin(), colon},
					trim(colon == line.end() ? "" : std::string_view{colon + 1, line.end()}),
					"\n");
		}
		return fields;
	}
}

#include "json/json.h"

#include <cmath>
#include <utility>

#include "utils.h"


namespace leaf::json {
	constexpr std::string_view whitespaces = "\x20\x09\x0a\x0d";

	void skip_ws(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		while (ptr != end && whitespaces.contains(*ptr))
			++ptr;
	}

	std::string parse_string(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		std::string value;
		if (*ptr++ != '"')
			throw malformed_json{};
		while (*ptr != '"') {
			if (*ptr == '\\') {
				++ptr;
				switch (*ptr) {
					case 'b': value.push_back('\b'); break;
					case 'f': value.push_back('\f'); break;
					case 'n': value.push_back('\n'); break;
					case 'r': value.push_back('\r'); break;
					case 't': value.push_back('\t'); break;
					case 'u': {
						++ptr;
						std::string code_point_str{ptr, std::next(ptr, 4)};
						auto code_point = std::stoi(code_point_str, nullptr, 16);
						if (code_point <= 0x7f)
							value.push_back(static_cast<char>(code_point));
						else if (code_point <= 0x7ff) {
							value.push_back(static_cast<char>(0b110 << 5 | code_point >> 6));
							value.push_back(static_cast<char>(0b10 << 6 | code_point & 0b111111));
						} else if (code_point <= 0xffff) {
							value.push_back(static_cast<char>(0b1110 << 4 | code_point >> 12));
							value.push_back(static_cast<char>(0b10 << 6 | code_point >> 6 & 0b111111));
							value.push_back(static_cast<char>(0b10 << 6 | code_point & 0b111111));
						} else {
							value.push_back(static_cast<char>(0b11110 << 3 | code_point >> 18));
							value.push_back(static_cast<char>(0b10 << 6 | code_point >> 12 & 0b111111));
							value.push_back(static_cast<char>(0b10 << 6 | code_point >> 6 & 0b111111));
							value.push_back(static_cast<char>(0b10 << 6 | code_point & 0b111111));
						}
						std::advance(ptr, 3);
						break;
					}
					default:
						value.push_back(*ptr);
				}
			} else
				value.push_back(*ptr);
			if (++ptr == end)
				throw malformed_json{};
		}
		++ptr;
		return value;
	}

	double parse_number(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		double value = 0;
		const bool minus = *ptr == '-' && ++ptr;
		if (*ptr == '0')
			++ptr;
		else while (ptr != end && '0' <= *ptr && *ptr <= '9')
				value = 10 * value + (*ptr++ - '0');
		if (*ptr == '.') {
			if ('0' > *++ptr || *ptr > '9')
				throw malformed_json{};
			double i = -1;
			while (ptr != end && '0' <= *ptr && *ptr <= '9')
				value += (*ptr++ - '0') * std::pow<double>(10, i--);
		}
		if (*ptr == 'e' || *ptr == 'E') {
			++ptr;
			*ptr == '+' && ++ptr;
			double exp = 0;
			const bool exp_minus = *ptr == '-' && ++ptr;
			while (ptr != end && '0' <= *ptr && *ptr <= '9')
				exp = 10 * exp + (*ptr++ - '0');
			value *= std::pow(10., exp_minus ? -exp : exp);
		}
		return minus ? -value : value;
	}

	std::shared_ptr<element> parse_element(std::string_view::const_iterator&, std::string_view::const_iterator);

	object::members_t parse_object(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		using namespace std::literals::string_view_literals;
		object::members_t members;
		skip_ws(ptr, end);
		if (*ptr++ != '{')
			throw malformed_json{};
		while (*ptr != '}') {
			skip_ws(ptr, end);
			std::string key = parse_string(ptr, end);
			skip_ws(ptr, end);
			if (*ptr++ != ':')
				throw malformed_json{};
			members.emplace(std::move(key), parse_element(ptr, end));
			if (*ptr == ',')
				++ptr;
			else if (*ptr != '}')
				throw malformed_json{};
		}
		skip_ws(++ptr, end);
		return members;
	}

	array::items_t parse_array(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		array::items_t items;
		skip_ws(ptr, end);
		if (*ptr++ != '[')
			throw malformed_json{};
		while (*ptr != ']') {
			skip_ws(ptr, end);
			items.emplace_back(parse_element(ptr, end));
		}
		return items;
	}

	void parse_null(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		if (std::distance(ptr, end) < 4 || !std::equal(ptr, ptr + 4, "null"))
			throw malformed_json{};
		std::advance(ptr, 4);
	}

	bool parse_boolean(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		if (std::distance(ptr, end) >= 4 && std::equal(ptr, ptr + 4, "true")) {
			std::advance(ptr, 4);
			return true;
		}
		if (std::distance(ptr, end) >= 5 && std::equal(ptr, ptr + 5, "false")) {
			std::advance(ptr, 5);
			return false;
		}
		throw malformed_json{};
	}

	std::shared_ptr<element> parse_element(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) { // NOLINT(*-no-recursion)
		std::shared_ptr<element> element;
		skip_ws(ptr, end);
		switch (*ptr) {
			case '{':
				element = std::make_shared<object>(parse_object(ptr, end));
				break;
			case '[':
				element = std::make_shared<array>(parse_array(ptr, end));
				break;
			case '"':
				element = std::make_shared<string>(parse_string(ptr, end));
				break;
			case 't': case 'f':
				element = std::make_shared<boolean>(parse_boolean(ptr, end));
				break;
			case 'n':
				parse_null(ptr, end);
				element = std::make_shared<null>();
				break;
			default:
				element = std::make_shared<number>(parse_number(ptr, end));
				break;
		}
		skip_ws(ptr, end);
		return element;
	}

	std::shared_ptr<element> element::parse(const std::string_view json_text) {
		auto ptr = json_text.begin();
		auto element = parse_element(ptr, json_text.end());
		return ptr != json_text.end() ? throw malformed_json{} : element;
	}

	object::object(const std::string_view source) {
		auto ptr = source.begin();
		skip_ws(ptr, source.end());
		if (*ptr++ != '{')
			throw malformed_json{};
		while (*ptr != '}') {
			skip_ws(ptr, source.end());
			std::string key = parse_string(ptr, source.end());
			skip_ws(ptr, source.end());
			if (*ptr++ != ':')
				throw malformed_json{};
			members.emplace(std::move(key), parse_element(ptr, source.end()));
		}
		skip_ws(++ptr, source.end());
		if (ptr != source.end())
			throw malformed_json{};
	}

	object::object(members_t members)
			: members(std::move(members)) {
	}

	array::array(items_t values)
			: items(std::move(values)) {
	}

	string::string(const std::string_view source) {
		auto ptr = source.begin();
		value = parse_string(ptr, source.end());
	}

	string::string(std::string value)
			: value(std::move(value)) {
	}

	number::number(const std::string_view source) {
		auto ptr = source.begin();
		value = parse_number(ptr, source.end());
	}

	number::number(const double value)
			: value(value) {
	}

	boolean::boolean(const bool value)
			: value(value) {
	}
}

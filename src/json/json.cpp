#include "json/json.h"
#include "utils.h"
#include <cmath>
#include <format>


namespace leaf::json {

	constexpr std::string_view whitespaces = "\x20\x09\x0a\x0d";

	const std::runtime_error malformed_json{"malformed json"};

	void skip_ws(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		while (ptr != end && whitespaces.contains(*ptr))
			++ptr;
	}

	std::string parse_string(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		std::string value;
		if (*ptr++ != '"')
			throw malformed_json;
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
							value.push_back(static_cast<char>(0b11000000 | code_point >> 6));
							value.push_back(static_cast<char>(0b10000000 | code_point & 0b111111));
						} else if (code_point <= 0xffff) {
							value.push_back(static_cast<char>(0b11100000 | code_point >> 12));
							value.push_back(static_cast<char>(0b10000000 | code_point >> 6 & 0b111111));
							value.push_back(static_cast<char>(0b10000000 | code_point & 0b111111));
						} else {
							value.push_back(static_cast<char>(0b11110000 | code_point >> 18));
							value.push_back(static_cast<char>(0b10000000 | code_point >> 12 & 0b111111));
							value.push_back(static_cast<char>(0b10000000 | code_point >> 6 & 0b111111));
							value.push_back(static_cast<char>(0b10000000 | code_point & 0b111111));
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
				throw malformed_json;
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
				throw malformed_json;
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

	element parse_element(std::string_view::const_iterator&, std::string_view::const_iterator);

	object::members_t parse_object(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		object::members_t members;
		skip_ws(ptr, end);
		if (*ptr++ != '{')
			throw malformed_json;
		while (*ptr != '}') {
			skip_ws(ptr, end);
			std::string key = parse_string(ptr, end);
			skip_ws(ptr, end);
			if (*ptr++ != ':')
				throw malformed_json;
			members.emplace(std::move(key), parse_element(ptr, end));
			skip_ws(ptr, end);
			if (*ptr == ',')
				++ptr;
			else if (*ptr != '}')
				throw malformed_json;
		}
		skip_ws(++ptr, end);
		return members;
	}

	array::items_t parse_array(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		array::items_t items;
		skip_ws(ptr, end);
		if (*ptr++ != '[')
			throw malformed_json;
		while (*ptr != ']') {
			skip_ws(ptr, end);
			items.emplace_back(parse_element(ptr, end));
		}
		return items;
	}

	void parse_null(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) {
		if (std::distance(ptr, end) < 4 || !std::equal(ptr, ptr + 4, "null"))
			throw malformed_json;
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
		throw malformed_json;
	}

	element parse_element(std::string_view::const_iterator& ptr, const std::string_view::const_iterator end) { // NOLINT(*-no-recursion)
		skip_ws(ptr, end);
		switch (*ptr) {
			case '{':
				return object{parse_object(ptr, end)};
			case '[':
				return array{parse_array(ptr, end)};
			case '"':
				return parse_string(ptr, end);
			case 't': case 'f':
				return parse_boolean(ptr, end);
			case 'n':
				parse_null(ptr, end);
				return nullptr;
			default:
				return parse_number(ptr, end);
		}
	}

	element parse(const std::string_view json_text) {
		auto ptr = json_text.begin();
		auto element = parse_element(ptr, json_text.end());
		return ptr != json_text.end() ? throw malformed_json : element;
	}

	std::string stringfy(const element& item) {
		if (std::holds_alternative<std::nullptr_t>(item))
			return "null";
		if (std::holds_alternative<double>(item))
			return std::format("{}", std::get<double>(item));
		if (std::holds_alternative<bool>(item))
			return std::get<bool>(item) ? "true" : "false";
		if (std::holds_alternative<std::string>(item)) {
			auto& origin = std::get<std::string>(item);
			std::string str = R"(")";
			for (auto it = origin.begin(), end = origin.end(); it != end; ++it) {
				if ((*it & 0b11110000) == 0b11110000 && (*(it + 1) & 0b10000000) == 0b10000000
						&& (*(it + 2) & 0b10000000) == 0b10000000 && (*(it + 3) & 0b10000000) == 0b10000000)
					str += std::format(R"(\u{:04x})", (*it & 0b111) << 18 | (*(it + 1) & 0b111111) << 12
							| (*(it + 2) & 0b111111) << 6 | *(it + 3) & 0b111111), std::advance(it, 3);
				else if ((*it & 0b11100000) == 0b11100000 && (*(it + 1) & 0b10000000) == 0b10000000
						&& (*(it + 2) & 0b10000000) == 0b10000000)
					str += std::format(R"(\u{:04x})", (*it & 0b1111) << 12 | (*(it + 1) & 0b111111) << 6
							| *(it + 2) & 0b111111), std::advance(it, 2);
				else if ((*it & 0b11100000) == 0b11100000 && (*(it + 1) & 0b10000000) == 0b10000000)
					str += std::format(R"(\u{:04x})", (*it & 0b11111) << 6 | (*(it + 1) & 0b111111)),
							std::advance(it, 1);
				else switch (*it) {
					case '"':
						str += R"(\")";
						break;
					case '\b':
						str += R"(\b)";
						break;
					case '\f':
						str += R"(\f)";
						break;
					case '\n':
						str += R"(\n)";
						break;
					case '\r':
						str += R"(\r)";
						break;
					case '\t':
						str += R"(\t)";
						break;
					default:
						str += *it;
				}
			}
			str += R"(")";
			return str;
		}
		if (std::holds_alternative<array>(item)) {
			std::string str = "[";
			for (bool first = true; auto& entry: std::get<array>(item).items) {
				str += first ? " " : ", ";
				str += stringfy(entry);
				first = false;
			}
			str += "]";
			return str;
		}
		if (std::holds_alternative<object>(item)) {
			std::string str = "{";
			for (bool first = true; auto& [key, value]: std::get<object>(item).members) {
				if (!first)
					str += ", ";
				str += std::format(R"("{}": {})", key, stringfy(value));
				first = false;
			}
			str += "}";
			return str;
		}
		throw std::runtime_error{"unexpected @ leaf::json::stringfy()"};
	}
}

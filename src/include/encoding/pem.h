#pragma once
#include "encoding/base64.h"
#include <format>

namespace encoding::pem {

	constexpr byte_string from(const std::string_view __v) {
		using std::literals::operator ""sv;
		const auto pem_begin = __v.find("-----BEGIN ");
		if (pem_begin == std::string_view::npos)
			throw std::runtime_error{"input does not contain any encoded message"};
		const auto label_begin = pem_begin + 11;
		const auto label_end = __v.find("-----\n", label_begin);
		if (label_end == std::string_view::npos)
			throw std::runtime_error{"ill-formed header"};
		const auto label = __v.substr(label_begin, label_end - label_begin);
		const auto data_begin = label_end + 6;
		const auto data_end = __v.find(std::format("-----END {}-----\n", label), data_begin);
		if (data_end == std::string_view::npos)
			throw std::runtime_error{"encoded message does not end with footer"};
		return base64::from(__v.substr(data_begin, data_end - data_begin));
	}
}

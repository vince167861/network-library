#pragma once
#include <string>
#include <cstdint>

namespace leaf::network::http2::internal {

	std::string from_huffman(std::basic_string_view<std::uint8_t> str);
}

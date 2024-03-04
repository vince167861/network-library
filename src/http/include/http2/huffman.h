#pragma once
#include "byte_string.h"

namespace network::http2::internal {

	std::string from_huffman(byte_string_view str);
}

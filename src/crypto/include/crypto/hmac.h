#pragma once
#include "big_number.h"
#include <functional>

namespace hashing {

	big_unsigned HMAC_hash(
			std::size_t block_size, const std::function<big_unsigned(const big_unsigned&)>& hash,
			const big_unsigned& data, const big_unsigned& key);

	byte_string HMAC_SHA_256(byte_string_view data, byte_string_view key);

	byte_string HMAC_sha_384(byte_string_view data, byte_string_view key);
}

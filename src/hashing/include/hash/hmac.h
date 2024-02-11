#pragma once

#include "number/flexible.h"

#include <functional>

namespace leaf::hashing {

	big_unsigned HMAC_hash(
			std::size_t block_size,
			const std::function<big_unsigned(const number_base&)>& hash,
			const number_base& data,
			const number_base& key
			);

	big_unsigned HMAC_sha_256(const number_base& data, const number_base& key);

	big_unsigned HMAC_sha_384(const number_base& data, const number_base& key);
}

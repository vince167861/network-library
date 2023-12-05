#pragma once

#include "number/flexible.h"

#include <functional>

namespace leaf::hashing {

	var_unsigned HMAC_hash(
			std::size_t block_size,
			const std::function<var_unsigned(const number_base&)>& hash,
			const number_base& data,
			const number_base& key
			);

	var_unsigned HMAC_sha_256(const number_base& data, const number_base& key);

	var_unsigned HMAC_sha_384(const number_base& data, const number_base& key);
}

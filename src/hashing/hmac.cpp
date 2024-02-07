#include "hash/hmac.h"

#include "hash/sha2.h"

namespace leaf::hashing {

	var_unsigned HMAC_hash(std::size_t block_size, const std::function<var_unsigned(const number_base&)>& hash, const number_base& data, const number_base& key_) {
		var_unsigned ipad(block_size * 8, 0x36363636), opad(block_size * 8, 0x5c5c5c5c);
		var_unsigned key = key_;
		auto&& cmp = key.bits() <=> block_size * 8;
		if (std::is_lt(cmp)) {
			key.resize(block_size * 8);
			key <<= block_size * 8 - key_.bits();
		} else if (std::is_gt(cmp))
			key = hash(key);
		auto ind = key ^ ipad;
		ind.resize(block_size * 8 + data.bits());
		ind <<= data.bits();
		ind.set(data);
		ind = hash(ind);
		auto ret = key ^ opad;
		ret.resize(block_size * 8 + ind.bits());
		ret <<= ind.bits();
		ret.set(ind);
		return hash(ret);
	}

	var_unsigned HMAC_sha_256(const number_base& data, const number_base& key) {
		return HMAC_hash(64, sha_256::hash, data, key);
	}

	var_unsigned HMAC_sha_384(const number_base& data, const number_base& key) {
		return HMAC_hash(128, sha_384::hash, data, key);
	}
}

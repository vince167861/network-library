#include "cipher/hmac.h"
#include "cipher/sha2.h"

namespace leaf::hashing {

	big_unsigned HMAC_hash(const std::size_t block_size, const std::function<big_unsigned(const big_unsigned&)>& hash, const big_unsigned& data, const big_unsigned& key_) {
		const big_unsigned ipad(byte_string(block_size, '\x36')), opad(byte_string(block_size, '\x5c'));
		big_unsigned key(key_);
		const auto cmp = key.bit_most() <=> block_size * 8;
		if (std::is_lt(cmp)) {
			key.resize(block_size * 8);
			key <<= (block_size - key_.size()) * 8;
		} else if (std::is_gt(cmp))
			key = hash(key);
		auto ind = key ^ ipad;
		ind.resize((block_size + data.size()) * 8);
		ind <<= data.size() * 8;
		ind.set({data});
		ind = hash(ind);
		auto ret = key ^ opad;
		ret.resize(block_size * 8 + ind.bit_most());
		ret <<= ind.bit_most();
		ret.set(ind);
		return hash(ret);
	}

	byte_string HMAC_SHA_256(byte_string_view data, byte_string_view key) {
		return HMAC_hash(64, sha_256::hash, {data, std::nullopt, std::endian::big}, {key, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}

	byte_string HMAC_sha_384(const byte_string_view data, const byte_string_view key) {
		return HMAC_hash(128, sha_384::hash, {data, std::nullopt, std::endian::big}, {key, std::nullopt, std::endian::big}).to_bytestring(std::endian::big);
	}
}

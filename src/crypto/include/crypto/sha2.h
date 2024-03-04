#pragma once
#include "big_number.h"

template<class T>
T rotate_right(T x, std::size_t D) {
	return x << sizeof(T) * 8 - D | x >> D;
}


class sha_256 {

	static uint32_t Sigma_0(const std::uint32_t x) {
		return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
	}

	static uint32_t Sigma_1(const std::uint32_t x) {
		return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
	}

	static uint32_t sigma_0(const std::uint32_t x) {
		return rotate_right(x, 7) ^ rotate_right(x, 18) ^ x >> 3;
	}

	static uint32_t sigma_1(const std::uint32_t x) {
		return rotate_right(x, 17) ^ rotate_right(x, 19) ^ x >> 10;
	}

public:
	static big_unsigned hash(const big_unsigned&);
};


class sha_384 {

	static uint64_t Sigma_0(const std::uint64_t x) {
		return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
	}

	static uint64_t Sigma_1(const std::uint64_t x) {
		return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
	}

	static uint64_t sigma_0(const std::uint64_t x) {
		return rotate_right(x, 1) ^ rotate_right(x, 8) ^ x >> 7;
	}

	static uint64_t sigma_1(const std::uint64_t x) {
		return rotate_right(x, 19) ^ rotate_right(x, 61) ^ x >> 6;
	}

public:
	static big_unsigned hash(const big_unsigned&);
};

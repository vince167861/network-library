#pragma once
#include "number/big_number.h"

namespace leaf::ecc {

	big_unsigned montgomery_curve(const big_unsigned& scalar, const big_unsigned& u_coordinate, std::size_t bits);

	inline auto x25519(big_unsigned scalar, big_unsigned u_coordinate) {
		scalar.resize(256);
		u_coordinate.resize(256);
		scalar.set_bit(0, false);
		scalar.set_bit(1, false);
		scalar.set_bit(2, false);
		scalar.set_bit(31 * 8 + 7, false);
		scalar.set_bit(31 * 8 + 6, true);
		return montgomery_curve(scalar, u_coordinate, 255);
	}
}

#pragma once
#include "number/flexible.h"
#include <iostream>

namespace leaf::ecc {

	inline var_signed p(const std::size_t bits) {
		if (bits == 255)
			return (big_unsigned(1, 256) << 255) - 19;
		else if (bits == 448)
			return (big_unsigned(1, 449) << 448) - (big_unsigned(1, 225) << 224) - 1;
		else
			throw std::runtime_error{"unexpected"};
	}

	template<class T>
	void c_swap(bool swap, T& a, T& b) {
		if (swap) std::swap(a, b);
	}

	inline auto montgomery_curve(const big_unsigned& scalar, const big_unsigned& u_coordinate, const std::size_t bits) {
		const var_signed a24(121665);
		auto _p = p(bits);

		var_signed x_1 = u_coordinate, x_2 = 1, z_2 = 0, x_3 = u_coordinate, z_3 = 1;
		bool swap = false;
		for (std::size_t t_ = bits + 1; t_ > 0; --t_) {
			auto t = t_ - 1;
			bool k_t = scalar.bit(t);
			swap = swap != k_t;
			c_swap(swap, x_2, x_3);
			c_swap(swap, z_2, z_3);
			swap = k_t;

			auto A = x_2 + z_2;
			auto AA = A * A;
			auto B = x_2 - z_2;
			auto BB = B * B;
			auto E = AA - BB;
			auto C = x_3 + z_3;
			auto D = x_3 - z_3;
			auto DA = D * A;
			auto CB = C * B;
			auto DA_CB_1 = DA + CB;
			x_3 = (DA_CB_1 * DA_CB_1) % _p;
			auto DA_CB_2 = DA - CB;
			auto DA_CB_2_2 = DA_CB_2 * DA_CB_2;
			z_3 = x_1 * DA_CB_2_2 % _p;
			x_2 = AA * BB % _p;
			auto a24_E = E * a24;
			auto AA_a24_E = AA + a24_E;
			z_2 = E * AA_a24_E % _p;
		}
		c_swap(swap, x_2, x_3);
		c_swap(swap, z_2, z_3);
		return x_2 * exp_mod(z_2, _p - 2, _p) % _p;
	}


	inline auto x25519(big_unsigned scalar, big_unsigned u_coordinate) {
		scalar.resize(255);
		u_coordinate.resize(255);
		scalar.set(false, 0);
		scalar.set(false, 1);
		scalar.set(false, 2);
		scalar.set(false, 31 * 8 + 7);
		scalar.set(true, 31 * 8 + 6);
		return montgomery_curve(scalar, u_coordinate, 255);
	}
}

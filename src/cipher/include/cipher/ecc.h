#pragma once
#include "number/flexible.h"
#include <iostream>

namespace leaf::ecc {

	var_signed p(const std::size_t bits) {
		if (bits == 255) {
			auto ret = var_unsigned::from_number(1);
			ret.resize(256);
			return (ret << 255) - var_unsigned::from_number(19);
		} else if (bits == 448) {
			auto ret_1 = var_unsigned::from_number(1);
			ret_1.resize(449);
			auto ret_2 = var_unsigned::from_number(1);
			ret_2.resize(225);
			return (ret_1 << 448) - (ret_2 << 224) - var_unsigned::from_number(1);
		} else
			throw std::runtime_error{"unexpected"};
	}

	template<class T>
	void c_swap(bool swap, T& a, T& b) {
		if (swap) std::swap(a, b);
	}

	auto montgomery_curve(const var_unsigned& scalar, const var_unsigned& u_coordinate, const std::size_t bits) {
		var_signed _2(2), a24(121665);
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
		return x_2 * exp_mod(z_2, _p - _2, _p) % _p;
	}


	inline auto x25519(var_unsigned scalar, const var_unsigned& u_coordinate) {
		scalar.set(false, 0);
		scalar.set(false, 1);
		scalar.set(false, 2);
		scalar.set(false, 31 * 8 + 7);
		scalar.set(true, 31 * 8 + 6);
		return montgomery_curve(scalar, u_coordinate, 255);
	}
}

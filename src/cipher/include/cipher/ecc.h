#pragma once
#include "number/fixed.h"

namespace leaf::ecc {

	template<std::size_t bits>
	consteval fixed_signed<bits> p() {
		if constexpr (bits == 255)
			return (fixed_unsigned<256>(1) << 255) - fixed_unsigned(19);
		else if constexpr (bits == 448)
			return (fixed_unsigned<449>(1) << 448) - (fixed_unsigned<225>(1) << 224) - fixed_unsigned(1);
		else
			throw std::exception{};
	}

	template<std::size_t bits>
	void c_swap(bool swap, fixed_unsigned<bits>& a, fixed_unsigned<bits>& b) {
		if (swap) std::swap(a, b);
	}

	template<std::size_t bits>
	auto montgomery_curve(const fixed_unsigned<bits>& scalar, const fixed_unsigned<bits>& u_coordinate) {
		using operand_t = fixed_signed<bits>;
		constexpr fixed_signed _2(2), a24(121665);
		constexpr auto _p = p<bits>();

		operand_t x_1 = u_coordinate, x_2 = 1, z_2 = 0, x_3 = u_coordinate, z_3 = 1;
		bool swap = false;
		for (std::size_t t_ = bits + 1; t_ > 0; --t_) {
			auto t = t_ - 1;
			bool k_t = scalar.bit(t);
			swap = swap != k_t;
			c_swap(swap, x_2, x_3);
			c_swap(swap, z_2, z_3);
			swap = k_t;

			auto&& A = x_2 + z_2;
			auto&& AA = A * A;
			auto&& B = x_2 - z_2;
			auto&& BB = B * B;
			auto&& E = AA - BB;
			operand_t&& C = x_3 + z_3;
			operand_t&& D = x_3 - z_3;
			auto&& DA = D * A;
			auto&& CB = C * B;
			auto&& DA_CB_1 = DA + CB;
			x_3 = (DA_CB_1 * DA_CB_1) % _p;
			auto&& DA_CB_2 = DA - CB;
			auto&& DA_CB_2_2 = DA_CB_2 * DA_CB_2;
			z_3 = x_1 * DA_CB_2_2 % _p;
			x_2 = AA * BB % _p;
			auto&& a24_E = E * a24;		// order of `a24` and `E` is important for now (implicit casting)
			auto&& AA_a24_E = AA + a24_E;
			z_2 = E * AA_a24_E % _p;
		}
		c_swap(swap, x_2, x_3);
		c_swap(swap, z_2, z_3);
		return x_2 * operand_t(exp_mod(z_2, _p - _2, _p)) % _p;
	}


	inline auto x25519(fixed_unsigned<255> scalar, const fixed_unsigned<255>& u_coordinate) {
		scalar.set(0, false);
		scalar.set(1, false);
		scalar.set(2, false);
		scalar.set(31 * 8 + 7, false);
		scalar.set(31 * 8 + 6, true);
		return montgomery_curve<255>(scalar, u_coordinate);
	}
}

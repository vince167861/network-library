#include "cipher/ecc.h"

namespace leaf::ecc {

	inline big_unsigned p_(const std::size_t bits) {
		switch (bits) {
			case 255:
				return (big_unsigned(1u, 256) << 255) - 19u;
			case 448:
				return (big_unsigned(1u, 449) << 448) - (big_unsigned(1u, 225) << 224) - 1u;
			default:
				throw std::runtime_error{"unexpected"};
		}
	}

	inline big_unsigned a24_(const std::size_t bits) {
		switch (bits) {
			case 255:
				return 121665u;
			case 448:
				return 39081u;
			default:
				throw std::invalid_argument("unexpected bits");
		}
	}

	template<class T>
	void c_swap(bool swap, T& a, T& b) {
		if (swap) std::swap(a, b);
	}

	big_unsigned montgomery_curve(const big_unsigned& scalar, const big_unsigned& u_coordinate, const std::size_t bits) {
		const big_signed a24 = a24_(bits);
		const auto p = p_(bits);

		big_signed x_1 = u_coordinate, x_2 = 1, z_2 = 0, x_3 = u_coordinate, z_3 = 1;
		bool swap = false;
		for (std::size_t t = bits; t <= bits; --t) {
			bool k_t = scalar.test(t);
			swap = swap != k_t;
			c_swap(swap, x_2, x_3);
			c_swap(swap, z_2, z_3);
			swap = k_t;

			const auto A = x_2 + z_2;
			const auto AA = A * A;
			const auto B = x_2 - z_2;
			const auto BB = B * B;
			const auto E = AA - BB;
			const auto C = x_3 + z_3;
			const auto D = x_3 - z_3;
			const auto DA = D * A;
			const auto CB = C * B;
			const auto DA_CB_1 = DA + CB;
			x_3 = DA_CB_1 * DA_CB_1 % p;
			const auto DA_CB_2 = DA - CB;
			z_3 = x_1 * (DA_CB_2 * DA_CB_2) % p;
			x_2 = AA * BB % p;
			z_2 = E * (AA + a24 * E) % p;
		}
		c_swap(swap, x_2, x_3);
		c_swap(swap, z_2, z_3);
		return {x_2 * exp_mod(z_2, p - 2u, p) % p};
	}
}

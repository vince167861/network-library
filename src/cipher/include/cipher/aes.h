#pragma once

#include "number/flexible.h"

namespace leaf {

	class aes {

		/// number of uint32_t of cipher key
		const std::size_t N_k;

		/// number of uint32_t of state
		const std::size_t N_b;

		/// number of rounds
		const std::size_t N_r;

		const std::size_t key_schedule_units = N_b * (N_r + 1);

	public:
		constexpr aes(std::size_t N_k, std::size_t N_b, std::size_t N_r)
				: N_k(N_k), N_b(N_b), N_r(N_r) {
		}

		static std::uint8_t GF_multiply(std::uint8_t, std::uint8_t);

		static void shift_rows(big_unsigned& state);

		void inv_shift_rows(big_unsigned& state) const;

		void mix_columns(big_unsigned& state) const;

		void inv_mix_columns(big_unsigned& state) const;

		void add_round_key(big_unsigned& state, const big_unsigned& key_schedule, std::size_t round) const;

		void cipher(big_unsigned& val, const big_unsigned& key_schedule) const;

		void inv_cipher(big_unsigned& val, const big_unsigned& key_schedule) const;

		void key_expansion(const big_unsigned& key, big_unsigned& key_schedule) const;
	};

	constexpr aes aes_128{4, 4, 10}, aes_256{8, 4, 14};
}

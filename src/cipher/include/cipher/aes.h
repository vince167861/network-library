#pragma once

#include "number/big_number.h"

namespace leaf {

	struct aes {

		/// number of uint32_t of cipher key
		const std::size_t N_k;

		/// number of uint32_t of state
		const std::size_t N_b;

		/// number of rounds
		const std::size_t N_r;

		const std::size_t key_schedule_units = N_b * (N_r + 1);

		constexpr aes(std::size_t N_k, std::size_t N_b, std::size_t N_r)
				: N_k(N_k), N_b(N_b), N_r(N_r) {
		}

		static std::uint8_t GF_multiply(std::uint8_t, std::uint8_t);

		void shift_rows(big_unsigned& state, bool inverse) const;

		void mix_columns(big_unsigned& state, bool inverse) const;

		void add_round_key(big_unsigned& state, const big_unsigned& key_schedule, std::size_t round) const;

		void cipher(big_unsigned& val, const big_unsigned& key_schedule) const;

		void inv_cipher(big_unsigned& val, const big_unsigned& key_schedule) const;

		void key_expansion(const big_unsigned& key, big_unsigned& key_schedule) const;

		static void rotation_left(big_unsigned& state, std::size_t row, std::size_t shift);

		static std::uint32_t rotation_left(std::uint32_t val);

		static void sub_bytes(big_unsigned& state, bool inverse);

		static std::uint32_t sub_bytes(std::uint32_t);
	};

	constexpr aes aes_128{4, 4, 10}, aes_256{8, 4, 14};
}

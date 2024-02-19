#pragma once
#include "number/big_number.h"

namespace leaf {

	class gcm {

		big_unsigned pre_counter_(const big_unsigned& iv) const;

		big_unsigned tag_(const big_unsigned& ciphertext, const big_unsigned& pre_counter, const big_unsigned& auth_data) const;

	public:
		static constexpr std::size_t block_size = 128;

		const std::size_t key_bits, iv_bits, tag_bits;

	protected:
		big_unsigned hash_subkey_;

		/**
		 * Initialize hash subkey (per GCM spec).
		 *
		 * \note
		 * `init()` _must_ be called after `ciph` function is ready (e.g., key schedule is generated).
		 * Subclasses must call `init()` once before calling any other function.
		 */
		void init();

		gcm(const std::size_t key_size, const std::size_t iv_size, const std::size_t tag_size)
			: key_bits(key_size), iv_bits(iv_size), tag_bits(tag_size) {
		}

	public:
		/// Function CIPH of GCM spec. Should at least cipher a `var_unsigned` of `block_size` bits.
		virtual big_unsigned ciph(const big_unsigned& X) const = 0;

		/**
		 * Function GCM-AE_k of GCM spec.
		 * @param iv initialization vector
		 * @param plaintext plain text
		 * @param auth_data additional authentication data
		 * @return pair of ciphered text and authentication tag
		 */
		std::pair<big_unsigned, big_unsigned>
		encrypt(const big_unsigned& iv, const big_unsigned& plaintext, const big_unsigned& auth_data) const;

		big_unsigned
		decrypt(const big_unsigned& iv, const big_unsigned& cipher, const big_unsigned& auth_data, const big_unsigned& tag) const;

		/// function GHASH of GCM spec
		big_unsigned ghash(const big_unsigned& val) const;

		/// function GCTR of GCM spec.
		big_unsigned gctr(big_unsigned ICB, const big_unsigned& X) const;

		static big_unsigned multiply(const big_unsigned&, big_unsigned);
	};

	big_unsigned increase(const std::size_t size, big_unsigned);
}

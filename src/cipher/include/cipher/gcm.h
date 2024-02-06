#pragma once
#include "number/fixed.h"
#include "number/flexible.h"

namespace leaf {

	class gcm {
	public:
		static constexpr std::size_t block_size = 128;

		const std::size_t key_size, iv_size, tag_size;

	protected:
		var_unsigned hash_subkey_;

		/**
		 * Initialize hash subkey (per GCM spec).
		 *
		 * \note
		 * `init()` _must_ be called after `ciph` function is ready (e.g., key schedule is generated).
		 * Subclasses must call `init()` once before the use of any function.
		 */
		void init();

		gcm(const std::size_t key_size, const std::size_t iv_size, const std::size_t tag_size)
			: key_size(key_size), iv_size(iv_size), tag_size(tag_size) {
		}

	public:
		/**
		 * Function CIPH of GCM spec. Should at least cipher a `var_unsigned` of `block_size` bits.
		 */
		virtual var_unsigned ciph(const var_unsigned& X) const = 0;

		/**
		 * Function GCM-AE_k of GCM spec.
		 * @param iv initialization vector
		 * @param plain plain text
		 * @param data additional authentication data
		 * @return pair of ciphered text and authentication tag
		 */
		std::pair<var_unsigned, var_unsigned>
		encrypt(const var_unsigned& iv, const var_unsigned& plain, const var_unsigned& data) const;

		var_unsigned decrypt(const var_unsigned& iv, const var_unsigned& cipher, const var_unsigned& data, const var_unsigned& tag) const;

		// function GHASH of GCM spec
		var_unsigned ghash(const var_unsigned& val) const;

		/** function GCTR of GCM spec. */
		var_unsigned gctr(var_unsigned ICB, const var_unsigned& X) const;
	};

	var_unsigned increase(const std::size_t bits, var_unsigned val);
}

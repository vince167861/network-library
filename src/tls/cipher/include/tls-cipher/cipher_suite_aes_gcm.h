#pragma once
#include "cipher_suite.h"
#include "cipher_suite_gcm.h"
#include "cipher/aes.h"

namespace leaf::network::tls {

	class aes_128_gcm: public cipher_suite_gcm {

		big_unsigned key_schedule;

		big_unsigned ciph(const big_unsigned& X) const override;

	public:
		void set_key(const big_unsigned&) override;

		aes_128_gcm();
	};


	struct aes_128_gcm_sha256 final: aes_128_gcm {

		byte_string hash(byte_string_view) const override;

		byte_string HMAC_hash(byte_string_view data, byte_string_view key) const override;

		aes_128_gcm_sha256();
	};


	class aes_256_gcm: public cipher_suite_gcm {

		big_unsigned key_schedule;

		big_unsigned ciph(const big_unsigned& X) const override;

	public:
		void set_key(const big_unsigned&) override;

		aes_256_gcm();
	};


	struct aes_256_gcm_sha384 final: public aes_256_gcm {

		byte_string hash(byte_string_view hash) const override;

		byte_string HMAC_hash(byte_string_view data, byte_string_view key) const override;

		aes_256_gcm_sha384();
	};
}

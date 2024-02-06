#pragma once

#include "cipher_suite.h"
#include "cipher_suite_gcm.h"
#include "cipher/aes.h"


namespace leaf::network::tls {


	class aes_128_gcm: public cipher_suite_gcm {

		var_unsigned key_schedule;

		var_unsigned ciph(const var_unsigned& X) const override;

	public:
		void set_key(const number_base& secret_key) override;

		aes_128_gcm();
	};


	class aes_128_gcm_sha256 final: public aes_128_gcm {
	public:
		std::string hash(std::string_view hash) const override;

		std::string HMAC_hash(std::string_view data, std::string_view key) const override;

		aes_128_gcm_sha256();
	};


	class aes_256_gcm: public cipher_suite_gcm {

		var_unsigned key_schedule;

		var_unsigned ciph(const var_unsigned& X) const override;

	public:
		void set_key(const number_base& secret_key) override;

		aes_256_gcm();
	};


	class aes_256_gcm_sha384 final: public aes_256_gcm {
	public:
		std::string hash(std::string_view hash) const override;

		std::string HMAC_hash(std::string_view data, std::string_view key) const override;

		aes_256_gcm_sha384();
	};
}

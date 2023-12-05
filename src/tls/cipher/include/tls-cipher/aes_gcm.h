#pragma once

#include "cipher_suite.h"
#include "gcm_cipher.h"
#include "cipher/aes.h"


namespace leaf::network::tls {


	class aes_128_gcm: public gcm_cipher {
		var_unsigned key_schedule;

		void print(std::ostream& ostream) const override;

	protected:
		var_unsigned ciph(const var_unsigned& X) const override {
			auto X_copied = X;
			aes_128::cipher(X_copied, key_schedule);
			return X_copied;
		}

	public:
		void set_key(const number_base& secret_key) override {
			var_unsigned secret_key_(secret_key);
			aes_128::key_expansion(secret_key_, key_schedule);
			init();
		}

		aes_128_gcm();

	};

	class aes_128_gcm_sha256 final: public aes_128_gcm {
	public:
		std::string hash(std::string_view hash) const override;

		std::string HMAC_hash(std::string_view data, std::string_view key) const override;

		aes_128_gcm_sha256();

	};

	class aes_256_gcm: public gcm_cipher {
		var_unsigned key_schedule;

		void print(std::ostream& ostream) const override;

	protected:
		var_unsigned ciph(const var_unsigned& X) const override {
			auto X_copied = X;
			aes_256::cipher(X_copied, key_schedule);
			return X_copied;
		}

	public:
		void set_key(const number_base& secret_key) override {
			var_unsigned secret_key_(secret_key);
			aes_256::key_expansion(secret_key_, key_schedule);
			init();
		}

		aes_256_gcm();

	};

	class aes_256_gcm_sha384 final: public aes_256_gcm {
	public:
		std::string hash(std::string_view hash) const override;

		std::string HMAC_hash(std::string_view data, std::string_view key) const override;

		aes_256_gcm_sha384();
	};
}

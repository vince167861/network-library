#pragma once
#include "manager.h"
#include "tls-utils/rng.h"

namespace leaf::network::tls {

	class x25519_manager: public key_exchange_manager {
	public:
		using key_t = fixed_unsigned<32 * 8>;

	private:
		bool has_key;

		key_t secret_key;
		key_t public_key_;
		key_t shared_key_;

	public:
		explicit x25519_manager(const key_t& secret_key);

		explicit x25519_manager();

		void generate_private_key(random_number_generator&) override;

		void exchange_key(std::string_view remote_public_key) override;

		void exchange_key(const key_t& remote_public_key);

		std::string public_key() override;

		std::string shared_key() const override;

		bool key_ready() const override;
	};
}

#pragma once
#include "manager.h"
#include "tls-utils/rng.h"

namespace leaf::network::tls {

	class x25519_manager: public key_exchange_manager {
	private:
		bool has_key;

		big_unsigned secret_key;
        big_unsigned public_key_;
        big_unsigned shared_key_;

	public:
		explicit x25519_manager(const big_unsigned& secret_key);

		explicit x25519_manager();

		void generate_private_key(random_number_generator&) override;

		void exchange_key(std::string_view remote_public_key) override;

		void exchange_key(const big_unsigned& remote_public_key);

		std::string public_key() override;

		std::string shared_key() const override;

		bool key_ready() const override;
	};
}

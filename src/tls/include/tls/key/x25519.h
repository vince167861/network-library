#pragma once
#include "manager.h"
#include "big_number.h"

namespace network::tls {

	class x25519_manager: public key_exchange_manager {

		bool has_key;

		big_unsigned secret_key_, public_key_, shared_key_;

	public:
		explicit x25519_manager();

		explicit x25519_manager(big_unsigned secret_key);

		byte_string public_key() const override;

		byte_string shared_key() const override;

		bool ready() const override;

		void generate(random_source&) override;

		void exchange(byte_string_view remote_public_key) override;
	};
}

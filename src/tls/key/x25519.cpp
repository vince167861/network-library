#include "tls/key/x25519.h"
#include "crypto/ecc.h"

namespace network::tls {

	x25519_manager::x25519_manager()
			: key_exchange_manager(named_group_t::x25519), has_key(false) {
	}

	x25519_manager::x25519_manager(big_unsigned secret_key)
			: key_exchange_manager(named_group_t::x25519), has_key(true), secret_key_(std::move(secret_key)) {
		public_key_ = crypto::ecc::x25519(secret_key_, 9u);
	}

	byte_string x25519_manager::public_key() const {
		return public_key_.to_bytestring(std::endian::little);
	}

	byte_string x25519_manager::shared_key() const {
		return shared_key_.to_bytestring(std::endian::little);
	}

	bool x25519_manager::ready() const {
		return has_key;
	}

	void x25519_manager::generate(random_source& generator) {
		secret_key_ = {generator(32)};
		public_key_ = crypto::ecc::x25519(secret_key_, 9u);
		has_key = true;
	}

	void x25519_manager::exchange(const byte_string_view remote_public_key) {
		shared_key_ = crypto::ecc::x25519(secret_key_, {remote_public_key});
	}
}

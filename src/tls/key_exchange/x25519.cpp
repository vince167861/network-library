#include "tls-key/x25519.h"

#include "tls-key/ecc.h"

namespace leaf::network::tls {

	x25519_manager::x25519_manager(const key_t& secret_key)
			: key_exchange_manager(named_group_t::x25519), has_key(true), secret_key(secret_key), public_key_(ecc::x25519(secret_key, 9)) {
	}

	x25519_manager::x25519_manager()
			: key_exchange_manager(named_group_t::x25519), has_key(false) {
	}

	std::string x25519_manager::public_key() {
		return public_key_.to_bytestring(std::endian::little);
	}

	void x25519_manager::exchange_key(std::string_view remote_public_key) {
		const key_t remote_key = var_unsigned::from_little_endian_bytes(remote_public_key);
		exchange_key(remote_key);
	}

	void x25519_manager::exchange_key(const key_t& remote_public_key) {
		shared_key_ = ecc::x25519(secret_key, remote_public_key);
	}

	std::string x25519_manager::shared_key() const {
		return shared_key_.to_bytestring(std::endian::little);
	}

	bool x25519_manager::key_ready() const {
		return has_key;
	}

	void x25519_manager::generate_private_key(random_number_generator& generator) {
		for (auto& u: secret_key.data)
			u = generator.unit();
		public_key_ = ecc::x25519(secret_key, 9);
		has_key = true;
	}

}

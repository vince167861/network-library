#include "tls-key/ffdhe2048.h"

namespace leaf::network::tls {

	ffdhe2048_manager::ffdhe2048_manager(const var_unsigned& secret_key)
			: key_exchange_manager(named_group_t::ffdhe2048), secret_key(secret_key),
			public_key_(exp_mod(var_unsigned::from_number(2), secret_key, ffdhe2048_p)), has_key(true) {}

	ffdhe2048_manager::ffdhe2048_manager()
			: key_exchange_manager(named_group_t::ffdhe2048), has_key(false) {
	}

	std::string ffdhe2048_manager::public_key() {
		return public_key_.to_bytestring(std::endian::big);
	}

	void ffdhe2048_manager::exchange_key(std::string_view remote_public_key) {
		shared_key_ = exp_mod(var_unsigned::from_bytes(remote_public_key), secret_key, ffdhe2048_p);
	}

	std::string ffdhe2048_manager::shared_key() const {
		return shared_key_.to_bytestring(std::endian::big);
	}

	bool ffdhe2048_manager::key_ready() const {
		return has_key;
	}

	void ffdhe2048_manager::generate_private_key(random_number_generator& generator) {
		for (auto& u: secret_key.data)
			u = generator.unit();
		public_key_ = exp_mod(var_unsigned::from_number(2), secret_key, ffdhe2048_p);
		has_key = true;
	}
}

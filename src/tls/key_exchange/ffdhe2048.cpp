#include "tls-key/ffdhe2048.h"
#include <algorithm>

namespace leaf::network::tls {

	ffdhe2048_manager::ffdhe2048_manager()
			: key_exchange_manager(named_group_t::ffdhe2048), has_key(false) {
	}

	ffdhe2048_manager::ffdhe2048_manager(big_unsigned secret_key)
			: key_exchange_manager(named_group_t::ffdhe2048), secret_key_(std::move(secret_key)), has_key(true) {
		public_key_ = exp_mod(2u, secret_key_, ffdhe2048_p);
	}

	byte_string ffdhe2048_manager::public_key() const {
		byte_string str(public_key_.size(), 0);
		std::ranges::reverse_copy(public_key_, str.begin());
		return str;
	}

	byte_string ffdhe2048_manager::shared_key() const {
		byte_string str(shared_key_.size(), 0);
		std::ranges::reverse_copy(shared_key_, str.begin());
		return str;
	}

	bool ffdhe2048_manager::ready() const {
		return has_key;
	}

	void ffdhe2048_manager::generate(random_number_generator& generator) {
		secret_key_ = {generator.number(32)};
		public_key_ = exp_mod(2u, secret_key_, ffdhe2048_p);
		has_key = true;
	}

	void ffdhe2048_manager::exchange(const byte_string_view remote_public_key) {
		shared_key_ = exp_mod({remote_public_key, std::nullopt, std::endian::big}, secret_key_, ffdhe2048_p);
	}
}

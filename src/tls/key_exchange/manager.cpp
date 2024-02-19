#include "tls-key/manager.h"

#include "tls-key/ffdhe2048.h"
#include "tls-key/x25519.h"

namespace leaf::network::tls {

	key_exchange_manager::key_exchange_manager(named_group_t ng)
			: group(ng) {
	}

	std::unique_ptr<key_exchange_manager> get_key_manager(const named_group_t group, random_number_generator& rng) {
		std::unique_ptr<key_exchange_manager> ptr;
		switch (group) {
			case named_group_t::ffdhe2048:
				ptr = std::make_unique<ffdhe2048_manager>();
				break;
			case named_group_t::x25519:
				ptr = std::make_unique<x25519_manager>();
				break;
			default:
				ptr = std::make_unique<unimplemented_group>(group);
				break;
		}
		ptr->generate(rng);
		return ptr;
	}
}

#include "tls-key/manager.h"

#include "tls-key/ffdhe2048.h"
#include "tls-key/x25519.h"

namespace leaf::network::tls {

	key_exchange_manager::key_exchange_manager(named_group_t ng)
			: group(ng) {
	}

	key_exchange_manager* get_key_manager(const std::string_view str) {
		if (str == "ffdhe2048")
			return new ffdhe2048_manager;
		if (str == "x25519")
			return new x25519_manager;
		return nullptr;
	}
}

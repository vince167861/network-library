#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	key_update::key_update(std::string_view source) {
		auto ptr = source.begin();
		reverse_read(ptr, request_update);
	}

	key_update::key_update(bool request)
		: request_update(request ? key_update_request::update_requested : key_update_request::update_not_requested) {
	}

	void key_update::format(std::format_context::iterator& it) const {
		it = std::ranges::copy("KeyUpdate: ", it).out;
		switch (request_update) {
			case key_update_request::update_requested:
				it = std::ranges::copy("Update requested", it).out;
				break;
			case key_update_request::update_not_requested:
				it = std::ranges::copy("Update not requested (echo)", it).out;
				break;
		}
	}

	std::string key_update::to_bytestring() const {
		std::string str;
		reverse_write(str, handshake_type_t::key_update);
		reverse_write(str, 1);
		return str + static_cast<char>(request_update);
	}
}

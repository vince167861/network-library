#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	key_update::key_update(std::string_view source)
			: handshake(handshake_type_t::key_update, true) {
		auto ptr = source.begin();
		reverse_read(ptr, request_update);
	}

	key_update::key_update(bool request)
			: handshake(handshake_type_t::key_update, true),
			request_update(request ? key_update_request::update_requested : key_update_request::update_not_requested) {
	}

	std::string key_update::build_handshake_() const {
		std::string msg;
		msg.push_back(static_cast<char>(request_update));
		return msg;
	}

	void key_update::print(std::ostream& s) const {
		s << "KeyUpdate\n\t";
		switch (request_update) {
			case key_update_request::update_requested:
				s << "Update requested";
				break;
			case key_update_request::update_not_requested:
				s << "Update not requested (echo)";
				break;
		}
		s << '\n';
	}
}

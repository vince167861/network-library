#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	key_update::key_update(std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, request_update, ptr);
	}

	key_update::key_update(bool request)
		: request_update(request ? key_update_request::update_requested : key_update_request::update_not_requested) {
	}

	std::format_context::iterator key_update::format(std::format_context::iterator it) const {
		it = std::ranges::copy("KeyUpdate: ", it).out;
		switch (request_update) {
			case key_update_request::update_requested:
				it = std::ranges::copy("Update requested", it).out;
				break;
			case key_update_request::update_not_requested:
				it = std::ranges::copy("Update not requested (echo)", it).out;
				break;
			default:
				throw std::runtime_error{"unexpected"};
		}
		return it;
	}

	std::string key_update::to_bytestring(std::endian) const {
		std::string str;
		write(std::endian::big, str, handshake_type_t::key_update);
		write(std::endian::big, str, 1, 3);
		return str + static_cast<char>(request_update);
	}
}

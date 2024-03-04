#include "tls-record/handshake.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	key_update::key_update(const byte_string_view source) {
		auto it = source.begin();
		read(std::endian::big, request_update, it);
	}

	key_update::key_update(const bool request)
		: request_update(request ? key_update_request::update_requested : key_update_request::update_not_requested) {
	}

	key_update::operator byte_string() const {
		byte_string str;
		write(std::endian::big, str, handshake_type_t::key_update);
		write(std::endian::big, str, 1, 3);
		return str + static_cast<std::uint8_t>(request_update);
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
}

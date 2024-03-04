#include "tls-extension/extension.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	session_ticket::session_ticket(const byte_string_view data)
			: data(data) {
	}

	void session_ticket::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::format_to(it, "session_ticket: {}", data);
	}

	session_ticket::operator byte_string() const {
		byte_string out;
		write(std::endian::big, out, ext_type_t::session_ticket);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}
}

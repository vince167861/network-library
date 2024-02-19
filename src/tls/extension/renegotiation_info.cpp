#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	renegotiation_info::renegotiation_info(byte_string_view verify_data)
		: renegotiated_connection(verify_data) {
	}

	void renegotiation_info::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::format_to(it, "renegotiation_info: {}", renegotiated_connection);
	}

	renegotiation_info::operator byte_string() const {
		byte_string data;
		write(std::endian::big, data, renegotiated_connection.size(), 1);
		byte_string out;
		write(std::endian::big, out, ext_type_t::renegotiation_info);
		write<ext_data_size_t>(std::endian::big, out, data.size() + renegotiated_connection.size());
		return out + data + renegotiated_connection;
	}
}

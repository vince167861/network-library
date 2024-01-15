#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	renegotiation_info::renegotiation_info(std::string_view verify_data)
		: renegotiated_connection(verify_data) {
	}

	void renegotiation_info::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::format_to(it, "renegotiation_info: {}", renegotiated_connection);
	}

	renegotiation_info::operator raw_extension() const {
		std::string data;
		reverse_write(data, renegotiated_connection.size(), 1);
		return {ext_type_t::renegotiation_info, std::move(data) + renegotiated_connection};
	}
}

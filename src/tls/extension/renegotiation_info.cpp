#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	renegotiation_info::renegotiation_info(std::string_view verify_data)
		: extension(ext_type_t::renegotiation_info), renegotiated_connection(verify_data) {
	}

	std::string renegotiation_info::build_() const {
		std::string ret;
		uint8_t size = renegotiated_connection.size();
		reverse_write(ret, size);
		return std::move(ret) + renegotiated_connection;
	}

	void renegotiation_info::print(std::ostream& s, std::size_t level) const {
		s << "renegotiation_info: " << renegotiated_connection;
	}
}

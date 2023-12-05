#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	record_size_limit::record_size_limit(uint16_t l)
		: extension(ext_type_t::record_size_limit), limit(l) {
	}

	std::string record_size_limit::build_() const {
		std::string msg;
		reverse_write(msg, limit);
		return msg;
	}

	void record_size_limit::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "record_size_limit:\n"
				<< std::string(level + 1, '\t') << "limit: " << limit << '\n';
	}
}

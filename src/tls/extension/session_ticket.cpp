#include "tls-extension/extension.h"

namespace leaf::network::tls {

	session_ticket::session_ticket(std::string_view data)
		: extension(ext_type_t::session_ticket), data(data) {
	}

	std::string session_ticket::build_() const {
		return data;
	}

	void session_ticket::print(std::ostream& s, std::size_t level) const {
		s << "session_ticket: " << data;
	}
}

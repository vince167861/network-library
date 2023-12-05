#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	new_session_ticket::new_session_ticket(std::string_view source, context& context)
			: handshake(handshake_type_t::new_session_ticket, true) {
		auto ptr = source.begin();
		reverse_read(ptr, ticket_lifetime);
		reverse_read(ptr, ticket_age_add);
		uint8_t n_size;
		reverse_read(ptr, n_size);
		ticket_nonce = {ptr, ptr + n_size};
		ptr += n_size;
		uint16_t t_size;
		reverse_read(ptr, t_size);
		ticket = {ptr, ptr + t_size};
		ptr += t_size;
		uint16_t ext_size;
		reverse_read(ptr, ext_size);
		while (ptr != source.end())
			extensions.emplace_back(extension::parse(context, ptr, *this));
	}

	std::string new_session_ticket::build_handshake_() const {
		std::string msg;
		reverse_write(msg, ticket_lifetime);
		reverse_write(msg, ticket_age_add);
		uint8_t n_size = ticket_nonce.size();
		reverse_write(msg, n_size);
		msg += ticket_nonce;
		uint16_t t_size = ticket.size();
		reverse_write(msg, t_size);
		msg += ticket;
		std::string ext;
		for (auto& e: extensions)
			ext += e->build();
		uint16_t ext_size = ext.size();
		reverse_write(msg, ext_size);
		msg += ext;
		return msg;
	}

	void new_session_ticket::print(std::ostream& s) const {
		s << "NewSessionTicket\n\tLifetime: " << ticket_lifetime << "\n\tAge add: " << ticket_age_add << '\n';
		s << "\tNonce: " << ticket_nonce << "\n\tTicket: " << ticket << "\n\tExtensions:\n";
		if (extensions.empty())
			s << "\t\t(empty)\n";
		else for (auto& ext: extensions)
			ext->print(s, 2);
	}
}

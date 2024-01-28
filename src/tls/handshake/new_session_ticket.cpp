#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	new_session_ticket::new_session_ticket(std::string_view source) {
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
		for (std::string_view ext_data{ptr, std::next(ptr, ext_size)}; !ext_data.empty(); ) {
			auto ext = parse_extension(ext_data);
			if (!ext) break;
			extensions.push_back(std::move(ext.value()));
		}
	}

	void new_session_ticket::format(std::format_context::iterator& it) const {
		it = std::format_to(it,
			"NewSessionTicket\n\tLifetime: {}\n\tAge add: {}\n\tNonce: {}\n\tTicket: {}\n\tExtensions:",
			ticket_lifetime, ticket_age_add, ticket_nonce, ticket);
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: extensions)
			it = std::format_to(it, "\n{}", ext);
	}

		std::string data, exts;
		reverse_write(data, ticket_lifetime);
		reverse_write(data, ticket_age_add);
		reverse_write(data, ticket_nonce.size(), 1);
	std::string new_session_ticket::to_bytestring(std::endian) const {
		data += ticket_nonce;
		reverse_write(data, ticket.size(), 2);
		data += ticket;
		for (auto& ext: extensions)
			exts += ext.to_bytestring();
		reverse_write(data, exts.size(), 2);
		data += exts;
		std::string str;
		reverse_write(str, handshake_type_t::new_session_ticket);
		reverse_write(str, data.size(), 3);
		return str + data;
	}
}

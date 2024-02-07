#include "tls-record/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	new_session_ticket::new_session_ticket(std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, ticket_lifetime, ptr);
		read(std::endian::big, ticket_age_add, ptr);
		ticket_nonce = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		ticket = read_bytestring(ptr, read<std::uint16_t>(std::endian::big, ptr));
		const auto ext_size = read<ext_size_t>(std::endian::big, ptr);
		for (std::string_view ext_data{ptr, std::next(ptr, ext_size)}; !ext_data.empty(); ) {
			auto ext = parse_extension(ext_data);
			if (!ext) break;
			extensions.push_back(std::move(ext.value()));
		}
	}

	std::format_context::iterator new_session_ticket::format(std::format_context::iterator it) const {
		it = std::format_to(it,
			"NewSessionTicket\n\tLifetime: {}\n\tAge add: {}\n\tNonce: {}\n\tTicket: {}\n\tExtensions:",
			ticket_lifetime, ticket_age_add, ticket_nonce, ticket);
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: extensions)
			it = std::format_to(it, "\n{}", ext);
		return it;
	}

	std::string new_session_ticket::to_bytestring(std::endian) const {
		std::string exts;
		for (auto& ext: extensions)
			exts += ext.to_bytestring();

		std::string data;
		write(std::endian::big, data, ticket_lifetime);
		write(std::endian::big, data, ticket_age_add);
		write(std::endian::big, data, ticket_nonce.size(), 1);
		data += ticket_nonce;
		write(std::endian::big, data, ticket.size(), 2);
		data += ticket;
		write(std::endian::big, data, exts.size(), 2);
		data += exts;

		std::string str;
		write(std::endian::big, str, handshake_type_t::new_session_ticket);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}
}

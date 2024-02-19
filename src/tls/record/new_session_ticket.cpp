#include "tls-record/handshake.h"
#include "utils.h"
#include <ranges>

namespace leaf::network::tls {

	new_session_ticket::new_session_ticket(const byte_string_view source) {
		auto it = source.begin();
		read(std::endian::big, ticket_lifetime, it);
		read(std::endian::big, ticket_age_add, it);
		ticket_nonce = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
		ticket = read_bytestring(it, read<std::uint16_t>(std::endian::big, it));
		const auto ext_size = read<ext_size_t>(std::endian::big, it);
		const auto end = std::next(it, ext_size);
		if (end > source.end())
			throw std::runtime_error("incomplete NewSessionTicket");
		for (byte_string_view ext_data(it, end); !ext_data.empty(); ) {
			auto ext = parse_extension(ext_data, extension_holder_t::other);
			if (!ext) break;
			add(ext.value().first, std::move(ext.value().second));
		}
	}

	new_session_ticket::operator byte_string() const {
		byte_string exts;
		for (auto __t: extensions_order)
			exts += *extensions.at(__t);

		byte_string data;
		write(std::endian::big, data, ticket_lifetime);
		write(std::endian::big, data, ticket_age_add);
		write(std::endian::big, data, ticket_nonce.size(), 1);
		data += ticket_nonce;
		write(std::endian::big, data, ticket.size(), 2);
		data += ticket;
		write(std::endian::big, data, exts.size(), 2);
		data += exts;

		byte_string str;
		write(std::endian::big, str, handshake_type_t::new_session_ticket);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator new_session_ticket::format(std::format_context::iterator it) const {
		it = std::format_to(it,
			"NewSessionTicket\n\tLifetime: {}\n\tAge add: {}\n\tNonce: {}\n\tTicket: {}\n\tExtensions:",
			ticket_lifetime, ticket_age_add, ticket_nonce, ticket);
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: std::views::values(extensions))
			it = std::format_to(it, "\n{}", *ext);
		return it;
	}
}

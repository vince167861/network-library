#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	void extension_holder::add(const ext_type_t __t, std::unique_ptr<extension_base> __e) {
		if (extensions.insert_or_assign(__t, std::move(__e)).second)
			extensions_order.push_back(__t);
	}

	const extension_base& extension_holder::get(const ext_type_t __t) const {
		if (!extensions.contains(__t))
			throw std::range_error(std::format("{} is absent", __t));
		return *extensions.at(__t);
	}

	std::expected<handshake, std::string>
	parse_handshake(byte_string_view& source, const bool encrypted, const bool established) {
		auto it = source.begin();

		const auto type = read<handshake_type_t>(std::endian::big, it);
		const auto length = read<std::uint32_t>(std::endian::big, it, 3);

		if (length > source.size() - sizeof(handshake_type_t) - 3)
			return "message incomplete";

		const auto end = std::next(it, length);
		const byte_string_view content(it, end);
		source = {end, source.end()};

		if (!encrypted) switch (type) {
			case handshake_type_t::client_hello:
				return client_hello(content);
			case handshake_type_t::server_hello:
				return server_hello(content);
			default:
				throw alert::unexpected_message();
		}
		if (!established) switch (type) {
			case handshake_type_t::encrypted_extensions:
				return encrypted_extension(content);
			case handshake_type_t::certificate:
				return certificate(content);
			case handshake_type_t::certificate_verify:
				return certificate_verify(content);
			case handshake_type_t::finished:
				return finished(content);
			default:
				throw alert::unexpected_message();
		}
		switch (type) {
			case handshake_type_t::new_session_ticket:
				return new_session_ticket(content);
			case handshake_type_t::key_update:
				return key_update(content);
			default:
				throw alert::unexpected_message();
		}
	}

	byte_string message_hash(const cipher_suite& cipher, const byte_string_view data) {
		byte_string msg;
		write(std::endian::big, msg, handshake_type_t::message_hash);
		write(std::endian::big, msg, cipher.digest_length, 3);
		msg += cipher.hash(data);
		return msg;
	}
}

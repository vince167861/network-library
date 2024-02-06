#include "tls-handshake/handshake.h"
#include "tls-context/endpoint.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	std::optional<handshake> parse_handshake(endpoint& context, std::string_view& source, const bool encrypted) {
		auto ptr = source.begin();

		const auto type = read<handshake_type_t>(std::endian::big, ptr);
		const auto length = read<std::uint32_t>(std::endian::big, ptr, 3);

		if (length > source.size() - sizeof(handshake_type_t) - 3)
			return {};

		const auto end = std::next(ptr, length);
		const std::string_view content{ptr, end};
		source = {end, source.end()};

		if (!encrypted)
			switch (type) {
				case handshake_type_t::client_hello:
					return client_hello{content};
				case handshake_type_t::server_hello:
					return server_hello{content};
				default:
					throw alert::unexpected_message();
			}
		switch (type) {
			case handshake_type_t::encrypted_extensions:
				return encrypted_extension{content};
			case handshake_type_t::certificate:
				return certificate{content};
			case handshake_type_t::certificate_verify:
				return certificate_verify{content};
			case handshake_type_t::finished:
				return finished{content, context.active_cipher_suite()};
			case handshake_type_t::new_session_ticket:
				return new_session_ticket{content};
			case handshake_type_t::key_update:
				return key_update{content};
			default:
				throw alert::unexpected_message();
		}
	}

	certificate_request::certificate_request(std::string_view source) {
		auto ptr = source.begin();
		certificate_request_context = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		const auto ext_size = read<std::uint16_t>(std::endian::big, ptr);
		if (const auto available = std::distance(ptr, source.end()); available < ext_size)
			throw alert::decode_error_early_end_of_data("certificate_list.size", available, ext_size);
		std::string_view ext_fragments{ptr, std::next(ptr, ext_size)};
		while (true) {
			auto ext = parse_extension(ext_fragments);
			if (!ext) break;
			extensions.push_back(std::move(ext.value()));
		}
	}

	std::string certificate_request::to_bytestring(std::endian) const {
		std::string exts;
		for (auto& ext: extensions)
			exts += ext.to_bytestring();

		std::string data;
		write(std::endian::big, data, certificate_request_context.size(), 1);
		data += certificate_request_context;
		write(std::endian::big, data, exts.size(), 2);
		data += exts;

		std::string str;
		write(std::endian::big, str, handshake_type_t::certificate_request);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	void certificate_request::format(std::format_context::iterator& it) const {
		it = std::format_to(it, "CertificateRequest");
	}

	std::string message_hash(const cipher_suite& cipher, const std::string_view data) {
		std::string msg;
		write(std::endian::big, msg, handshake_type_t::message_hash);
		msg.append({0, 0});
		write(std::endian::big, msg, cipher.digest_length, 1);
		msg += cipher.hash(data);
		return msg;
	}
}

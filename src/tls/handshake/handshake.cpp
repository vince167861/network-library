#include "tls-handshake/handshake.h"
#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	std::shared_ptr<handshake> handshake::parse(context& context, std::string_view::const_iterator& ptr, bool encrypted) {
		handshake_type_t type;
		uint32_t length = 0;

		reverse_read(ptr, type);
		reverse_read<3>(ptr, length);

		std::string_view content(ptr, ptr + length);
		ptr += length;

		std::shared_ptr<handshake> ret;

		if (!encrypted)
			switch (type) {
			case handshake_type_t::client_hello:
				ret.reset(new client_hello(content, context));
				break;
			case handshake_type_t::server_hello:
				ret.reset(new server_hello(content, context));
				break;
			default:
				throw alert::unexpected_message();
			}
		else
			switch (type) {
			case handshake_type_t::encrypted_extensions:
				ret.reset(new encrypted_extension(content, context));
				break;
			case handshake_type_t::certificate:
				ret.reset(new certificate(content, context));
				break;
			case handshake_type_t::certificate_verify:
				ret.reset(new certificate_verify(content));
				break;
			case handshake_type_t::finished:
				ret.reset(new finished(content, context));
				break;
			case handshake_type_t::new_session_ticket:
				ret.reset(new new_session_ticket(content, context));
				break;
			case handshake_type_t::key_update:
				ret.reset(new key_update(content));
				break;
			default:
				throw alert::unexpected_message();
			}
		return ret;
	}

	std::string handshake::build_content_() {
		std::string msg;
		auto&& data = build_handshake_();
		uint32_t D = data.size();

		reverse_write(msg, handshake_type);
		reverse_write(msg, D, 3);
		msg += data;

		return msg;
	}

	handshake::handshake(handshake_type_t type, bool encrypted)
			: record(content_type_t::handshake, encrypted), handshake_type(type) {
	}

	certificate_request::certificate_request(std::string_view source, context& context)
			: handshake(handshake_type_t::certificate_request, true) {
		auto ptr = source.begin();
		uint8_t c_size;
		reverse_read(ptr, c_size);
		certificate_request_context = {ptr, ptr + c_size};
		uint16_t ext_size;
		reverse_read(ptr, ext_size);
		auto available = std::distance(ptr, source.end());
		if (available < ext_size)
			throw alert::decode_error_early_end_of_data("certificate_list.size", available, ext_size);
		while (ptr != source.end())
			extensions.emplace_back(extension::parse(context, ptr, *this));
	}

	std::string message_hash(cipher_suite& cipher, client_hello& client_hello) {
		std::string msg;
		auto t = handshake::handshake_type_t::message_hash;
		reverse_write(msg, t);
		msg.append({0, 0});
		auto s = static_cast<uint8_t>(cipher.digest_length);
		reverse_write(msg, s);
		msg += cipher.hash(client_hello.build_content_());
		return msg;
	}
}

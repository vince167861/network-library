#include "tls-record/alert.h"
#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	constexpr uint8_t retry_magic[] = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c";
	constexpr const char* TLS1_2_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x01";
	constexpr const char* TLS1_1_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x00";


	std::string server_hello::build_handshake_() const {
		std::string msg;
		//	legacy_version
		reverse_write(msg, legacy_version);
		//	random
		forward_write(msg, random);
		//	legacy_session_id_echo
		uint8_t echo_size = legacy_session_id_echo.size();
		reverse_write(msg, echo_size);
		msg += legacy_session_id_echo;
		//	cipher_suite
		reverse_write(msg, cipher_suite);
		//	legacy_compression_method == 0
		msg.push_back(static_cast<char>(legacy_compression_method));
		//	extensions
		std::string ext;
		for (auto& e: extensions)
			ext += e->build();
		extension_size_t size = ext.size();
		reverse_write(msg, size);
		msg += ext;
		return msg;
	}

	server_hello::server_hello(std::string_view source, context& context)
			: handshake(handshake_type_t::server_hello, false) {
		auto ptr = source.begin();
		//	legacy_version
		reverse_read(ptr, legacy_version);
		//	random
		forward_read(ptr, random);
		is_hello_retry_request = std::equal(random, random + 32, retry_magic);
		//	legacy_session_id_echo
		uint8_t e_size;
		reverse_read(ptr, e_size);
		legacy_session_id_echo = {ptr, ptr + e_size};
		ptr += e_size;
		//	cipher_suite
		reverse_read(ptr, cipher_suite);
		//	legacy_compression_method == 0
		reverse_read(ptr, legacy_compression_method);
		if (legacy_compression_method)
			throw std::exception{};
		extension_size_t size;
		//	extensions
		reverse_read(ptr, size);
		auto available = std::distance(ptr, source.end());
		if (available != size)
			throw alert::decode_error_early_end_of_data("ServerHello.extension", available, size);
		while (ptr != source.end())
			extensions.emplace_back(tls::extension::parse(context, ptr, *this));
	}

	server_hello::server_hello()
			: handshake{handshake_type_t::server_hello, false} {
	}

	void server_hello::print(std::ostream& s) const {
		s << (is_hello_retry_request ? "HelloRetryRequest" : "ServerHello")
			<< "\n\tlegacy_version: " << legacy_version << "\n\trandom: 0x";
		for (auto& u: random)
			s << std::hex << static_cast<uint32_t>(u);
		s << "\n\tlegacy_session_id_echo: ";
		if (legacy_session_id_echo.empty())
			s << "(empty)";
		else
			for (auto& u: legacy_session_id_echo)
				s << std::hex << static_cast<uint32_t>(u);
		s << "\n\tcipher_suites: " << cipher_suite << "\n\tExtensions:\n";
		for (auto& ext: extensions)
			ext->print(s, 2);
	}
}

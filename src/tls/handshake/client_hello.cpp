#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	std::string client_hello::build_handshake_() const {
		if (cipher_suites.empty())
			throw std::exception{};
		std::string msg;
		//	legacy_version
		reverse_write(msg, legacy_version);
		//	random
		forward_write(msg, random);
		//	legacy_session_id
		{
			msg.push_back(static_cast<char>(legacy_session_id.size()));
			msg += legacy_session_id;
		}
		//	cipher_suites
		{
			uint16_t c_size = cipher_suites.size() * sizeof(cipher_suite_t);
			reverse_write(msg, c_size);
			for (auto& suite: cipher_suites)
				reverse_write(msg, suite);
		}
		//	legacy_compression_method
		msg.push_back(1);
		msg.push_back(0);
		//	extensions
		{
			std::string ext_data;
			for (auto& ext: extensions)
				ext_data += ext->build();
			uint16_t extSize = ext_data.length();
			reverse_write(msg, extSize);
			msg += ext_data;
		}
		return msg;
	}

	client_hello::client_hello(const context& context)
			: handshake(handshake_type_t::client_hello, false) {
		for (auto& cs: context.cipher_suites)
			cipher_suites.push_back(cs->value);
	}

	client_hello::client_hello(std::string_view source, context& context)
			: handshake(handshake_type_t::client_hello, false) {
		auto ptr = source.begin();
		reverse_read(ptr, legacy_version);
		reverse_read(ptr, random);
		//	legacy_session_id
		uint8_t echo_size;
		reverse_read(ptr, echo_size);
		legacy_session_id = {ptr, ptr + echo_size};
		ptr += echo_size;
		//	cipher_suites
		uint16_t c_size;
		reverse_read(ptr, c_size);
		for (uint16_t i = 0; i < c_size / 2; ++i) {
			cipher_suite_t cs;
			reverse_read(ptr, cs);
			cipher_suites.push_back(cs);
		}
		//	legacy_compression_methods
		uint8_t lcm_size;
		reverse_read(ptr, lcm_size);
		legacy_compression_methods = {ptr, ptr += lcm_size};
		ptr += lcm_size;
		//	extensions
		extension_size_t ext_size;
		reverse_read(ptr, ext_size);
		auto available = std::distance(ptr, source.end());
		if (available != ext_size)
			throw alert::decode_error_early_end_of_data("ClientHello.extensions", available, ext_size);
		while (ptr != source.end())
			extensions.emplace_back(extension::parse(context, ptr, *this));
	}

	void client_hello::print(std::ostream& s) const {
		s << "ClientHello\n\tlegacy_version: " << legacy_version << "\n\trandom: 0x";
		for (auto& u: random)
			s << std::hex << static_cast<uint32_t>(u);
		s << "\n\tlegacy_session_id: 0x";
		if (legacy_session_id.empty())
			s << "0";
		else
			for (auto& u: legacy_session_id)
				s << std::hex << static_cast<uint8_t>(u);
		s << "\n\tcipher_suites: \n";
		if (cipher_suites.empty())
			s << "\t\t(empty)\n";
		else
			for (auto u: cipher_suites)
				s << "\t\t" << u << '\n';
		s << "\textensions:\n";
		for (auto& ext: extensions)
			ext->print(s, 2);
	}
}

#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	client_hello::client_hello(const context& context) {
		for (auto& cs: context.cipher_suites)
			cipher_suites.push_back(cs->value);
	}

	client_hello::client_hello(std::string_view source) {
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
		if (const auto available = std::distance(ptr, source.end()); available != ext_size)
			throw alert::decode_error_early_end_of_data("ClientHello.extensions", available, ext_size);
		std::string_view ext_fragments{ptr, std::next(ptr, ext_size)};
		while (!ext_fragments.empty()) {
			auto ext = parse_extension(ext_fragments);
			if (!ext) break;
			extensions.push_back(std::move(ext.value()));
		}
	}

	std::string client_hello::to_bytestring(std::endian) const {
		if (cipher_suites.empty())
			throw std::runtime_error{"at least one cipher suite is required to generate valid ClientHello."};
		std::string data;
		reverse_write(data, legacy_version);
		forward_write(data, random);
		data.push_back(static_cast<char>(legacy_session_id.size()));
		data += legacy_session_id;
		reverse_write(data, cipher_suites.size() * sizeof(cipher_suite_t), 2);
		for (auto& suite: cipher_suites)
			reverse_write(data, suite);
		data.append({1, 0}); // legacy_compression_method
		std::string ext_data;
		for (auto& ext: extensions)
			ext_data += ext.to_bytestring();
		reverse_write(data, ext_data.length(), 2);
		data += ext_data;
		std::string str;
		reverse_write(str, handshake_type_t::client_hello);
		reverse_write(str, data.size(), 3);
		return str + data;
	}

	void client_hello::format(std::format_context::iterator& it) const {
		using std::literals::operator ""sv;
		it = std::format_to(it, "ClientHello\n\tlegacy_version: {}\n\trandom: 0x", legacy_version);
		for (auto& u: random)
			it = std::format_to(it, "{:x}", u);
		it = std::ranges::copy("\n\tlegacy_session_id: 0x"sv, it).out;
		if (legacy_session_id.empty())
			*it++ = '0';
		else for (auto& u: legacy_session_id)
			it = std::format_to(it, "{:x}", u);
		it = std::ranges::copy("\n\tcipher_suites:", it).out;
		if (cipher_suites.empty())
			it = std::ranges::copy(" (empty)"sv, it).out;
		else for (auto u: cipher_suites)
			it = std::format_to(it, "\n\t\t{}", u);
		it = std::ranges::copy("\n\textensions:"sv, it).out;
		for (auto& ext: extensions)
			it = std::format_to(it, "\n\t\t{}", ext);
	}
}

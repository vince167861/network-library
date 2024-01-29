#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	client_hello::client_hello(const context& context)
		: legacy_compression_methods{"\0"} {
		for (auto& cs: context.cipher_suites)
			cipher_suites.push_back(cs->value);
	}

	client_hello::client_hello(std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, legacy_version, ptr);
		read(std::endian::little, random, ptr);
		legacy_session_id
			= read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		const auto c_size = read<std::uint16_t>(std::endian::big, ptr);
		for (std::uint16_t i = 0; i < c_size / 2; ++i)
			cipher_suites.push_back(read<cipher_suite_t>(std::endian::big, ptr));
		legacy_compression_methods
			= read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));

		const auto ext_size = read<extension_size_t>(std::endian::big, ptr);
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
		write(std::endian::big, data, legacy_version);
		write(std::endian::little, data, random);
		write(std::endian::big, data, legacy_session_id.size(), 1);
		data += legacy_session_id;
		write(std::endian::big, data, cipher_suites.size() * sizeof(cipher_suite_t), 2);
		for (auto& suite: cipher_suites)
			write(std::endian::big, data, suite);
		write(std::endian::big, data, legacy_compression_methods.size(), 1);
		data += legacy_compression_methods;

		std::string ext_data;
		for (auto& ext: extensions)
			ext_data += ext.to_bytestring();
		write(std::endian::big, data, ext_data.length(), 2);
		data += ext_data;

		std::string str;
		write(std::endian::big, str, handshake_type_t::client_hello);
		write(std::endian::big, str, data.size(), 3);
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

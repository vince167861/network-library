#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"
#include <ranges>

namespace leaf::network::tls {

	client_hello::client_hello(std::set<cipher_suite_t> suites)
			: cipher_suites(suites.begin(), suites.end()), compression_methods(reinterpret_cast<const std::uint8_t*>("\0"), 1) {
	}

	client_hello::client_hello(const byte_string_view __s) {
		auto it = __s.begin();
		read(std::endian::big, version, it);
		read(std::endian::little, random, it);
		session_id = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
		const auto c_size = read<std::uint16_t>(std::endian::big, it);
		for (std::uint16_t i = 0; i < c_size / 2; ++i)
			cipher_suites.push_back(read<cipher_suite_t>(std::endian::big, it));
		compression_methods = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));

		const auto __size = read<ext_size_t>(std::endian::big, it);
		const auto end = std::next(it, __size);
		if (end > __s.end())
			throw alert::decode_error("incomplete ClientHello");
		byte_string_view ext_fragments(it, end);
		while (!ext_fragments.empty()) {
			auto ext = parse_extension(ext_fragments, extension_holder_t::client_hello);
			if (!ext) break;
			add(ext.value().first, std::move(ext.value().second));
		}
	}

	client_hello::operator byte_string() const {
		if (cipher_suites.empty())
			throw std::runtime_error{"at least one cipher suite is required to generate valid ClientHello."};

		byte_string exts;
		for (auto type: extensions_order)
			exts += *extensions.at(type);

		byte_string data;
		write(std::endian::big, data, version);
		write(std::endian::little, data, random);
		write(std::endian::big, data, session_id.size(), 1);
		data += session_id;
		write(std::endian::big, data, cipher_suites.size() * sizeof(cipher_suite_t), 2);
		for (auto& suite: cipher_suites)
			write(std::endian::big, data, suite);
		write(std::endian::big, data, compression_methods.size(), 1);
		data += compression_methods;
		write(std::endian::big, data, exts.length(), 2);
		data += exts;

		byte_string str;
		write(std::endian::big, str, handshake_type_t::client_hello);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator client_hello::format(std::format_context::iterator it) const {
		it = std::format_to(it,
				"ClientHello\n\tlegacy_version: {}\n\trandom: {}\n\tlegacy_session_id: {}\n\tcipher_suites:",
				version, byte_string_view(random.begin(), 32), session_id);
		if (cipher_suites.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto u: cipher_suites)
			it = std::format_to(it, "\n\t\t{}", u);
		it = std::ranges::copy("\n\textensions:", it).out;
		for (auto& ext: std::views::values(extensions))
			it = std::format_to(it, "\n{:2}", *ext);
		return it;
	}
}

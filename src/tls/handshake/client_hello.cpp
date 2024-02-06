#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	using std::literals::operator""sv;

	client_hello::client_hello(std::set<cipher_suite_t> suites)
		: compression_methods("\0"sv), cipher_suites(suites.begin(), suites.end()) {
	}

	client_hello::client_hello(std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, version, ptr);
		read(std::endian::little, random, ptr);
		session_id = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		const auto c_size = read<std::uint16_t>(std::endian::big, ptr);
		for (std::uint16_t i = 0; i < c_size / 2; ++i)
			cipher_suites.push_back(read<cipher_suite_t>(std::endian::big, ptr));
		compression_methods = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));

		const auto ext_size = read<ext_size_t>(std::endian::big, ptr);
		if (const auto available = std::distance(ptr, source.end()); available != ext_size)
			throw alert::decode_error_early_end_of_data("ClientHello.extensions", available, ext_size);
		std::string_view ext_fragments{ptr, std::next(ptr, ext_size)};
		while (!ext_fragments.empty()) {
			auto ext = parse_extension(ext_fragments);
			if (!ext) break;
			auto& [type, data] = ext.value();
			extension_order_.push_back(type);
			extensions.emplace(type, std::move(data));
		}
	}

	std::string client_hello::to_bytestring(std::endian) const {
		if (cipher_suites.empty())
			throw std::runtime_error{"at least one cipher suite is required to generate valid ClientHello."};

		std::string exts;
		for (auto type: extension_order_)
			exts += generate_extension(type, extensions.at(type));

		std::string data;
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

		std::string str;
		write(std::endian::big, str, handshake_type_t::client_hello);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	void client_hello::format(std::format_context::iterator& it) const {
		using std::literals::operator ""sv;
		it = std::format_to(it, "ClientHello\n\tlegacy_version: {}\n\trandom: 0x", version);
		for (auto& u: random)
			it = std::format_to(it, "{:x}", u);
		it = std::ranges::copy("\n\tlegacy_session_id: 0x"sv, it).out;
		if (session_id.empty())
			*it++ = '0';
		else for (auto& u: session_id)
			it = std::format_to(it, "{:x}", u);
		it = std::ranges::copy("\n\tcipher_suites:", it).out;
		if (cipher_suites.empty())
			it = std::ranges::copy(" (empty)"sv, it).out;
		else for (auto u: cipher_suites)
			it = std::format_to(it, "\n\t\t{}", u);
		it = std::ranges::copy("\n\textensions:"sv, it).out;
		for (auto& ext: extensions)
			it = std::format_to(it, "\n\t\t{}", raw_extension{ext.first, ext.second});
	}

	void client_hello::add_extension(std::initializer_list<raw_extension> exts) {
		for (auto& [type, data]: exts) {
			extension_order_.push_back(type);
			extensions.emplace(type, std::move(data));
		}
	}
}

#include "tls-record/alert.h"
#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	constexpr uint8_t retry_magic[] = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c";
	constexpr const char* TLS1_2_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x01";
	constexpr const char* TLS1_1_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x00";


	server_hello::server_hello(const std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, version, ptr);
		read(std::endian::little, random, ptr);
		is_hello_retry_request = std::ranges::equal(random, retry_magic);
		session_id_echo = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		read(std::endian::big, cipher_suite, ptr);
		read(std::endian::big, compression_method, ptr);

		const auto size = read<ext_size_t>(std::endian::big, ptr);
		if (const auto available = std::distance(ptr, source.end()); available != size)
			throw alert::decode_error_early_end_of_data("ServerHello.extension", available, size);
		std::string_view ext_fragments{ptr, std::next(ptr, size)};
		while (!ext_fragments.empty()) {
			const auto ext = parse_extension(ext_fragments);
			if (!ext) break;
			auto& [type, data] = ext.value();
			extension_order_.push_back(type);
			extensions.emplace(type, std::move(data));
		}
	}

	std::string server_hello::to_bytestring(std::endian) const {
		std::string ext_fragment;
		for (auto type: extension_order_)
			ext_fragment += generate_extension(type, extensions.at(type));

		std::string data;
		write(std::endian::big, data, version);
		write(std::endian::little, data, random);
		write(std::endian::big, data, session_id_echo.size(), 1);
		data += session_id_echo;
		write(std::endian::big, data, cipher_suite);
		write(std::endian::big, data, compression_method);
		write(std::endian::big, data, ext_fragment.size(), 2);
		data += ext_fragment;

		std::string str;
		write(std::endian::big, str, handshake_type_t::server_hello);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator server_hello::format(std::format_context::iterator it) const {
		it = std::format_to(it, "{}\n\tlegacy_version: {}\n\trandom: 0x",
			is_hello_retry_request ? "HelloRetryRequest" : "ServerHello", version);
		for (auto u: random)
			it = std::format_to(it, "{:02x}", u);
		it = std::ranges::copy("\n\tlegacy_session_id_echo: ", it).out;
		if (session_id_echo.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto u: session_id_echo)
			it = std::format_to(it, "{:02x}", u);
		it = std::format_to(it, "\n\tcipher_suites: {}\n\tExtensions:", cipher_suite);
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& [type, data]: extensions)
			it = std::format_to(it, "\n\t\t{}", raw_extension{type, data});
		return it;
	}

	void server_hello::to_retry() {
		std::ranges::copy(retry_magic, random.begin());
	}

	void server_hello::add_extension(std::initializer_list<raw_extension> exts) {
		for (auto& [type, data]: exts) {
			extension_order_.push_back(type);
			extensions.emplace(type, std::move(data));
		}
	}
}

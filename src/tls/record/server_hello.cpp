#include "tls-record/alert.h"
#include "tls-record/handshake.h"
#include "internal/utils.h"
#include <ranges>

namespace leaf::network::tls {

	constexpr uint8_t retry_magic[] = "\xcf\x21\xad\x74\xe5\x9a\x61\x11\xbe\x1d\x8c\x02\x1e\x65\xb8\x91\xc2\xa2\x11\x16\x7a\xbb\x8c\x5e\x07\x9e\x09\xe2\xc8\xa8\x33\x9c";
	constexpr const char* TLS1_2_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x01";
	constexpr const char* TLS1_1_RANDOM_MAGIC = "\x44\x4F\x57\x4E\x47\x52\x44\x00";


	server_hello::server_hello(const byte_string_view __v) {
		auto it = __v.begin();
		read(std::endian::big, version, it);
		read(std::endian::little, random, it);
		is_hello_retry_request = std::equal(random.begin(), random.end(), retry_magic);
		session_id_echo = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
		read(std::endian::big, cipher_suite, it);
		read(std::endian::big, compression_method, it);

		const auto __size = read<ext_size_t>(std::endian::big, it);
		const auto __end = std::next(it, __size);
		if (__end > __v.end())
			throw std::runtime_error("incomplete ServerHello");
		byte_string_view __fragment(it, __end);
		while (!__fragment.empty()) {
			auto ext = parse_extension(__fragment, is_hello_retry_request ? extension_holder_t::hello_retry_request : extension_holder_t::server_hello);
			if (!ext)
				break;
			add(ext.value().first, std::move(ext.value().second));
		}
	}

	server_hello::operator byte_string() const {
		byte_string __out_3;
		for (auto type: extensions_order)
			__out_3 += *extensions.at(type);

		byte_string __out_2;
		write(std::endian::big, __out_2, version);
		write(std::endian::little, __out_2, random);
		write(std::endian::big, __out_2, session_id_echo.size(), 1);
		__out_2 += session_id_echo;
		write(std::endian::big, __out_2, cipher_suite);
		write(std::endian::big, __out_2, compression_method);
		write(std::endian::big, __out_2, __out_3.size(), 2);

		byte_string __out_1;
		write(std::endian::big, __out_1, handshake_type_t::server_hello);
		write(std::endian::big, __out_1, __out_2.size() + __out_3.size(), 3);
		return __out_1 + __out_2 + __out_3;
	}

	std::format_context::iterator server_hello::format(std::format_context::iterator it) const {
		it = std::format_to(it,
			"{}\n\tlegacy_version: {}\n\trandom: {}\n\tlegacy_session_id_echo: {}\n\tcipher_suites: {}\n\tExtensions:",
			is_hello_retry_request ? "HelloRetryRequest" : "ServerHello", version, byte_string_view(random), session_id_echo, cipher_suite);
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: std::views::values(extensions))
			it = std::format_to(it, "\n{:2}", *ext);
		return it;
	}

	void server_hello::to_retry() {
		std::ranges::copy(retry_magic, random.begin());
	}

}

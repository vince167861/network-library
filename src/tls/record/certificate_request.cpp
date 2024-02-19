#include "tls-record/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	certificate_request::certificate_request(const byte_string_view source) {
		auto it = source.begin();
		certificate_request_context = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
		const auto __size = read<std::uint16_t>(std::endian::big, it);
		const auto end = std::next(it, __size);
		if (end > source.end())
			throw std::runtime_error("incomplete CertificateRequest");
		byte_string_view ext_fragments(it, end);
		while (!ext_fragments.empty()) {
			auto ext = parse_extension(ext_fragments, extension_holder_t::other);
			if (!ext) break;
			add(ext.value().first, std::move(ext.value().second));
		}
	}

	certificate_request::operator byte_string() const {
		byte_string exts;
		for (auto __t: extensions_order)
			exts += *extensions.at(__t);

		byte_string data;
		write(std::endian::big, data, certificate_request_context.size(), 1);
		data += certificate_request_context;
		write(std::endian::big, data, exts.size(), 2);
		data += exts;

		byte_string str;
		write(std::endian::big, str, handshake_type_t::certificate_request);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator certificate_request::format(std::format_context::iterator it) const {
		return std::format_to(it, "CertificateRequest");
	}
}

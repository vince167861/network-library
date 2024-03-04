#include "tls-record/handshake.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	certificate_verify::certificate_verify(const byte_string_view source) {
		auto it = source.begin();
		read(std::endian::big, signature_scheme, it);
		signature = read_bytestring(it, read<std::uint16_t>(std::endian::big, it));
	}

	certificate_verify::operator byte_string() const {
		byte_string data;
		write(std::endian::big, data, signature_scheme);
		write(std::endian::big, data, signature.size(), 2);
		data += signature;

		byte_string str;
		write(std::endian::big, str, handshake_type_t::certificate_verify);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator certificate_verify::format(const std::format_context::iterator it) const {
		return std::format_to(it, "CertificateVerify\n\tscheme: {}\n\tsignature: {}", signature_scheme, signature);
	}
}

#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	certificate_verify::certificate_verify(std::string_view source) {
		auto ptr = source.begin();
		read(std::endian::big, signature_scheme, ptr);
		signature = read_bytestring(ptr, read<std::uint16_t>(std::endian::big, ptr));
	}

	std::string certificate_verify::to_bytestring(std::endian) const {
		std::string data;
		write(std::endian::big, data, signature_scheme);
		write(std::endian::big, data, signature.size(), 2);
		data += signature;

		std::string str;
		write(std::endian::big, str, handshake_type_t::certificate_verify);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	void certificate_verify::format(std::format_context::iterator& it) const {
		it = std::format_to(it, "CertificateVerify\n\tScheme: {}\n\tSignature: ", signature_scheme);
		for (auto c: signature)
			it = std::format_to(it, "{:02x}", c);
	}
}

#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	certificate_verify::certificate_verify(std::string_view source) {
		auto ptr = source.begin();
		reverse_read(ptr, signature_scheme);
		uint16_t size;
		reverse_read(ptr, size);
		signature = {ptr, ptr + size};
		ptr += size;
	}

	std::string certificate_verify::to_bytestring(std::endian) const {
		std::string data;
		reverse_write(data, signature_scheme);
		reverse_write(data, signature.size(), 2);
		data += signature;
		std::string str;
		reverse_write(str, handshake_type_t::certificate_verify);
		reverse_write(str, data.size(), 3);
		return str + data;
	}

	void certificate_verify::format(std::format_context::iterator& it) const {
		it = std::format_to(it, "CertificateVerify\n\tScheme: {}\n\tSignature: ", signature_scheme);
		for (auto c: signature)
			it = std::format_to(it, "{:02x}", c);
	}
}

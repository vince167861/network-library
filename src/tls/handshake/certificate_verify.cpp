#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	certificate_verify::certificate_verify(std::string_view source)
			: handshake(handshake_type_t::certificate_verify, true) {
		auto ptr = source.begin();
		reverse_read(ptr, signature_scheme);
		uint16_t size;
		reverse_read(ptr, size);
		signature = {ptr, ptr + size};
		ptr += size;
	}

	std::string certificate_verify::build_handshake_() const {
		std::string msg;
		reverse_write(msg, signature_scheme);
		uint16_t size = signature.size();
		reverse_write(msg, size);
		msg += signature;
		return msg;
	}

	void certificate_verify::print(std::ostream& s) const {
		s << "CertificateVerify\n\tScheme: " << signature_scheme << "\n\tSignature: ";
		for (auto c: signature)
			s << std::hex << std::setw(2) << std::setfill('0') << (static_cast<uint32_t>(c) & 0xff);
		s << '\n';
	}
}

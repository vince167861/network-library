#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {
	finished::finished(std::string_view source, context& context)
			: handshake(handshake_type_t::finished, true) {
		if (context.active_cipher().digest_length != source.length())
			throw alert::decrypt_error();
		verify_data = source;
	}

	std::string finished::build_handshake_() const {
		return verify_data;
	}

	void finished::print(std::ostream& s) const {
		s << "Finished\n\tVerify data: ";
		for (auto c: verify_data)
			s << std::hex << std::setw(2) << std::setfill('0') << (static_cast<uint32_t>(c) & 0xff);
		s << '\n';
	}

	finished::finished(context& context, std::string_view handshake_msgs)
			: handshake(handshake::handshake_type_t::finished, true) {
		auto& cipher = context.active_cipher();
		auto&& finished_key = cipher.HKDF_expand_label(context.client_handshake_traffic_secret.to_bytes(), "finished", "", cipher.digest_length);
		verify_data = cipher.HMAC_hash(cipher.hash(handshake_msgs), finished_key);
	}
}

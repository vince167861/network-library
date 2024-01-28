#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	finished::finished(std::string_view source, context& context) {
		if (context.active_cipher().digest_length != source.length())
			throw alert::decrypt_error();
		verify_data = source;
	}

	finished::finished(context& context, std::string_view handshake_msgs) {
		auto& cipher = context.active_cipher();
		auto&& finished_key = cipher.HKDF_expand_label(context.client_handshake_traffic_secret.to_bytestring(), "finished", "", cipher.digest_length);
		verify_data = cipher.HMAC_hash(cipher.hash(handshake_msgs), finished_key);
	}

	void finished::format(std::format_context::iterator& it) const {
		it = std::ranges::copy("Finished\n\tVerify data: ", it).out;
		for (auto c: verify_data)
			it = std::format_to(it, "{:#04x}", c);
	}

	std::string finished::to_bytestring(std::endian) const {
		std::string str;
		reverse_write(str, handshake_type_t::finished);
		reverse_write(str, verify_data.size(), 3);
		return str + verify_data;
	}
}

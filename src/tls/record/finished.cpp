#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	finished::finished(const std::string_view source, cipher_suite& suite) {
		if (suite.digest_length != source.length())
			throw alert::decrypt_error();
		verify_data = source;
	}

	std::format_context::iterator finished::format(std::format_context::iterator it) const {
		it = std::ranges::copy("Finished\n\tVerify data: ", it).out;
		for (std::uint8_t c: verify_data)
			it = std::format_to(it, "{:02x}", c);
		return it;
	}

	std::string finished::to_bytestring(std::endian) const {
		std::string str;
		write(std::endian::big, str, handshake_type_t::finished);
		write(std::endian::big, str, verify_data.size(), 3);
		return str + verify_data;
	}
}

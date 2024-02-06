#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	finished::finished(const std::string_view source, cipher_suite& suite) {
		if (suite.digest_length != source.length())
			throw alert::decrypt_error();
		verify_data = source;
	}

	void finished::format(std::format_context::iterator& it) const {
		it = std::ranges::copy("Finished\n\tVerify data: ", it).out;
		for (auto c: verify_data)
			it = std::format_to(it, "{:#04x}", c);
	}

	std::string finished::to_bytestring(std::endian) const {
		std::string str;
		write(std::endian::big, str, handshake_type_t::finished);
		write(std::endian::big, str, verify_data.size(), 3);
		return str + verify_data;
	}
}

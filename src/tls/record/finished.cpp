#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	finished::finished(const byte_string_view source, cipher_suite& suite) {
		if (suite.digest_length != source.length())
			throw alert::decrypt_error();
		verify_data = source;
	}

	finished::operator byte_string() const {
		byte_string str;
		write(std::endian::big, str, handshake_type_t::finished);
		write(std::endian::big, str, verify_data.size(), 3);
		return str + verify_data;
	}

	std::format_context::iterator finished::format(std::format_context::iterator it) const {
		return std::format_to(it, "Finished\n\tVerify data: {}", verify_data);
	}
}

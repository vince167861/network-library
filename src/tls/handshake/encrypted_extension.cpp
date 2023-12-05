#include "tls-handshake/handshake.h"
#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	encrypted_extension::encrypted_extension(std::string_view source, context& context)
			: handshake(handshake_type_t::encrypted_extensions, true) {
		auto ptr = source.begin();
		uint16_t size;
		reverse_read(ptr, size);
		if (const auto available = std::distance(ptr, source.end()); size > available)
			throw alert::decode_error_early_end_of_data("extensions.size", available, size);
		while (ptr != source.end())
			extensions.emplace_back(extension::parse(context, ptr, *this));
	}

	std::string encrypted_extension::build_handshake_() const {
		std::string exts;
		for (auto& ext: extensions)
			exts += ext->build();
		std::string msg;
		reverse_write<uint16_t>(msg, exts.size());
		msg += exts;
		return msg;
	}

	void encrypted_extension::print(std::ostream& s) const {
		s << "EncryptedExtension\n";
		if (extensions.empty())
			s << "\t(empty)\n";
		else
			for (auto& ext: extensions)
				if (ext)
					ext->print(s, 1);
				else
					s << "\t(unrecognized)\n";
	}
}

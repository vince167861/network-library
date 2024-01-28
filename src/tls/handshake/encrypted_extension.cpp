#include "tls-handshake/handshake.h"
#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	encrypted_extension::encrypted_extension(std::string_view source) {
		auto ptr = source.begin();
		uint16_t size;
		reverse_read(ptr, size);
		if (const auto available = std::distance(ptr, source.end()); size > available)
			throw alert::decode_error_early_end_of_data("extensions.size", available, size);
		for (std::string_view ext_fragments{ptr, std::next(ptr, size)}; !ext_fragments.empty(); ) {
			auto ext = parse_extension(ext_fragments);
			if (!ext) break;
			extensions.push_back(std::move(ext.value()));
		}
	}

	std::string encrypted_extension::to_bytestring(std::endian) const {
		std::string data, exts;
		for (auto& ext: extensions)
			exts += ext.to_bytestring();
		reverse_write(data, exts.size(), 2);
		data += exts;
		std::string str;
		reverse_write(str, handshake_type_t::encrypted_extensions);
		reverse_write(str, data.size(), 3);
		return str + data;
	}

	void encrypted_extension::format(std::format_context::iterator& it) const {
		it = std::ranges::copy("EncryptedExtension", it).out;
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: extensions)
			it = std::format_to(it, "{}", ext);
	}
}

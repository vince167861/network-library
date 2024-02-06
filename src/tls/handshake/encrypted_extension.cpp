#include "tls-handshake/handshake.h"
#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	encrypted_extension::encrypted_extension(std::string_view source) {
		auto ptr = source.begin();
		const auto size = read<std::uint16_t>(std::endian::big, ptr);
		if (const auto available = std::distance(ptr, source.end()); size > available)
			throw alert::decode_error_early_end_of_data("extensions.size", available, size);
		for (std::string_view ext_fragments{ptr, std::next(ptr, size)}; !ext_fragments.empty(); ) {
			auto ext = parse_extension(ext_fragments);
			if (!ext)
				break;
			auto& [type, data] = ext.value();
			extensions.emplace(type, std::move(data));
			extension_order_.push_back(type);
		}
	}

	std::string encrypted_extension::to_bytestring(std::endian) const {
		std::string data, exts;
		for (auto type: extension_order_)
			exts += generate_extension(type, extensions.at(type));
		write(std::endian::big, data, exts.size(), 2);
		data += exts;

		std::string str;
		write(std::endian::big, str, handshake_type_t::encrypted_extensions);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator encrypted_extension::format(std::format_context::iterator it) const {
		it = std::ranges::copy("EncryptedExtension", it).out;
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: extensions)
			it = std::format_to(it, "\n\t{}", raw_extension{ext.first, ext.second});
		return it;
	}
}

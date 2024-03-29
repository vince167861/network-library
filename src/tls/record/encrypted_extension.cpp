#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "internal/utils.h"
#include <ranges>

using namespace internal;

namespace network::tls {

	encrypted_extension::encrypted_extension(const byte_string_view __s) {
		auto it = __s.begin();
		const auto __size = read<std::uint16_t>(std::endian::big, it);
		const auto end = std::next(it, __size);
		if (end > __s.end())
			throw alert::decode_error("incomplete EncryptedExtension");
		for (byte_string_view ext_fragments(it, end); !ext_fragments.empty(); ) {
			auto ext = parse_extension(ext_fragments, extension_holder_t::other);
			if (!ext)
				break;
			add(ext.value().first, std::move(ext.value().second));
		}
	}

	encrypted_extension::operator byte_string() const {
		byte_string exts;
		for (auto type: extensions_order)
			exts += *extensions.at(type);

		byte_string data;
		write(std::endian::big, data, exts.size(), 2);

		byte_string str;
		write(std::endian::big, str, handshake_type_t::encrypted_extensions);
		write(std::endian::big, str, data.size() + exts.size(), 3);
		return str + data + exts;
	}

	std::format_context::iterator encrypted_extension::format(std::format_context::iterator it) const {
		it = std::ranges::copy("EncryptedExtension", it).out;
		if (extensions.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& ext: extensions | std::views::values)
			it = std::format_to(it, "\n{:1}", *ext);
		return it;
	}
}

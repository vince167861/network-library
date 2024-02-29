#include "tls-record/handshake.h"
#include "tls-record/alert.h"
#include "internal/utils.h"
#include <ranges>

namespace leaf::network::tls {

	certificate::certificate(const byte_string_view __s) {
		auto it = __s.begin();
		certificate_request_context = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
		const auto __size = read<std::uint32_t>(std::endian::big, it, 3);
		const auto end = std::next(it, __size);
		if (end > __s.end())
			throw alert::decode_error("incomplete Certificate");
		while (it != end) {
			certificate_entry entry;
			entry.data = read_bytestring(it, read<std::uint32_t>(std::endian::big, it, 3));
			const auto __esize = read<std::uint16_t>(std::endian::big, it);
			const auto eend = std::next(it, __esize);
			if (eend > __s.end())
				throw alert::decode_error("incomplete Certificate");
			byte_string_view ext_data(it, eend);
			while (!ext_data.empty()) {
				auto ext = parse_extension(ext_data, extension_holder_t::other);
				if (!ext) break;
				entry.add(ext.value().first, std::move(ext.value().second));
			}
			certificate_list.push_back(std::move(entry));
		}
	}

	certificate::operator byte_string() const {
		byte_string cert_list;
		for (auto& __ct: certificate_list) {
			byte_string ext;
			for (auto& e: __ct.extensions_order)
				ext += *__ct.extensions.at(e);

			write(std::endian::big, cert_list, __ct.data.size(), 3);
			cert_list += __ct.data;
			write(std::endian::big, cert_list, ext.size(), 2);
			cert_list += ext;
		}

		byte_string data;
		write(std::endian::big, data, certificate_request_context.size(), 1);
		data += certificate_request_context;
		write(std::endian::big, data, cert_list.size(), 3);
		data += cert_list;

		byte_string str;
		write(std::endian::big, str, handshake_type_t::certificate);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator certificate::format(std::format_context::iterator it) const {
		it = std::format_to(it, "Certificate\n\tcertificate request context: {}\n\tcertificate list:", certificate_request_context);
		for (auto& __ct: certificate_list) {
			it = std::format_to(it, "\n\t\tentry:\n\t\t\tdata: {}\n\t\t\textensions:", __ct.data);
			if (__ct.extensions.empty())
				it = std::ranges::copy(" (empty)", it).out;
			else for (auto& ext: __ct.extensions | std::views::values)
				it = std::format_to(it, "\n{:4}", *ext);
		}
		return it;
	}
}

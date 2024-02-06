#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	certificate::certificate(std::string_view source) {
		auto ptr = source.begin();
		certificate_request_context = read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr));
		const auto cl_size = read<std::uint32_t>(std::endian::big, ptr, 3);
		auto available = std::distance(ptr, source.end());
		if (available < cl_size)
			throw alert::decode_error_early_end_of_data("certificate_list.size", available, cl_size);
		while (ptr != source.end()) {
			certificate_entry entry;
			entry.data = read_bytestring(ptr, read<std::uint32_t>(std::endian::big, ptr, 3));
			const auto ext_size = read<std::uint16_t>(std::endian::big, ptr);
			std::string_view ext_data{ptr, ptr + ext_size};
			while (!ext_data.empty()) {
				auto ext = parse_extension(ext_data);
				if (!ext) break;
				entry.extensions.push_back(std::move(ext.value()));
			}
			certificate_list.push_back(std::move(entry));
		}
	}

	std::string certificate::to_bytestring(std::endian) const {
		std::string cert_list;
		for (const auto& [data, extensions]: certificate_list) {
			std::string ext;
			for (auto& e: extensions)
				ext += e.to_bytestring();

			write(std::endian::big, cert_list, data.size(), 3);
			cert_list += data;
			write(std::endian::big, cert_list, ext.size(), 2);
			cert_list += ext;
		}

		std::string data;
		write(std::endian::big, data, certificate_request_context.size(), 1);
		data += certificate_request_context;
		write(std::endian::big, data, cert_list.size(), 3);
		data += cert_list;

		std::string str;
		write(std::endian::big, str, handshake_type_t::certificate);
		write(std::endian::big, str, data.size(), 3);
		return str + data;
	}

	std::format_context::iterator certificate::format(std::format_context::iterator it) const {
		it = std::format_to(it, "Certificate\n\tCertificate request context: {}\n\tCertificate list:",
			certificate_request_context);
		for (const auto& [data, extensions]: certificate_list) {
			it = std::ranges::copy("\n\t\tEntry:\n\t\t\tData: ", it).out;
			for (std::uint8_t c: data)
				it = std::format_to(it, "{:02x}", c);
			it = std::ranges::copy("\n\t\t\tExtensions:", it).out;
			if (extensions.empty())
				it = std::ranges::copy(" (empty)", it).out;
			else for (auto& ext: extensions)
				it = std::format_to(it, "\n\t\t\t\t{}", ext);
		}
		return it;
	}
}

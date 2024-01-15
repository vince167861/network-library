#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	certificate::certificate(std::string_view source) {
		auto ptr = source.begin();
		uint8_t c_size;
		reverse_read(ptr, c_size);
		certificate_request_context = {ptr, ptr + c_size};
		ptr += c_size;
		uint32_t cl_size = 0;
		reverse_read<3>(ptr, cl_size);
		auto available = std::distance(ptr, source.end());
		if (available < cl_size)
			throw alert::decode_error_early_end_of_data("certificate_list.size", available, cl_size);
		while (ptr != source.end()) {
			certificate_entry entry;
			uint32_t d_size = 0;
			reverse_read<3>(ptr, d_size);
			entry.data = {ptr, ptr + d_size};
			ptr += d_size;
			uint16_t ext_size;
			reverse_read(ptr, ext_size);
			std::string_view ext_data{ptr, ptr + ext_size};
			while (!ext_data.empty()) {
				auto ext = parse_extension(ext_data);
				if (!ext) break;
				entry.extensions.push_back(std::move(ext.value()));
			}
			certificate_list.push_back(std::move(entry));
		}
	}

	std::string certificate::to_bytestring() const {
		std::string data;
		reverse_write(data, certificate_request_context.size(), 1);
		data += certificate_request_context;
		std::string cert_list;
		for (const auto& [data, extensions]: certificate_list) {
			reverse_write(cert_list, data.size(), 3);
			cert_list += data;
			std::string ext;
			for (auto& e: extensions)
				ext += e.to_bytestring();
			reverse_write(cert_list, ext.size(), 2);
			cert_list += ext;
		}
		reverse_write(data, cert_list.size(), 3);
		data += cert_list;
		std::string str;
		reverse_write(str, handshake_type_t::certificate);
		reverse_write(str, data.size(), 3);
		return str + data;
	}

	void certificate::format(std::format_context::iterator& it) const {
		it = std::format_to(it, "Certificate\n\tCertificate request context: {}\n\tCertificate list:",
			certificate_request_context);
		for (const auto& [data, extensions]: certificate_list) {
			it = std::ranges::copy("\n\t\tEntry:\n\t\t\tData: ", it).out;
			for (auto c: data)
				it = std::format_to(it, "{:04x}", c);
			it = std::ranges::copy("\n\t\t\tExtensions:", it).out;
			if (extensions.empty())
				it = std::ranges::copy(" (empty)", it).out;
			else for (auto& ext: extensions)
				it = std::format_to(it, "\n\t\t\t\t{}", ext);
		}
	}
}

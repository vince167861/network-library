#include "tls-handshake/handshake.h"
#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	certificate::certificate(std::string_view source, context& context)
			: handshake(handshake_type_t::certificate, true) {
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
			while (ptr != ptr + ext_size)
				entry.extensions.emplace_back(extension::parse(context, ptr, *this));
			certificate_list.push_back(std::move(entry));
		}
	}

	std::string certificate::build_handshake_() const {
		std::string msg;
		uint8_t c_size = certificate_request_context.size();
		reverse_write(msg, c_size);
		msg += certificate_request_context;
		std::string cert_list;
		for (auto& cert: certificate_list) {
			uint32_t d_size = cert.data.size();
			reverse_write(cert_list, d_size, 3);
			cert_list += cert.data;
			std::string ext;
			for (auto& e: cert.extensions)
				ext += e->build();
			uint16_t ext_size = ext.size();
			reverse_write(cert_list, ext_size);
			cert_list += ext;
		}
		uint32_t cl_size = cert_list.size();
		reverse_write(msg, cl_size, 3);
		msg += cert_list;
		return msg;
	}

	void certificate::print(std::ostream& s) const {
		s << "Certificate\n\tCertificate request context: " << certificate_request_context << "\n\tCertificate list:\n";
		for (auto& cert: certificate_list) {
			s << "\t\tEntry:\n\t\t\tData: ";
			for (auto c: cert.data)
				s << std::hex << std::setfill('0') << std::setw(2) << (static_cast<uint32_t>(c) & 0xff);
			s << "\n\t\t\tExtensions:\n";
			if (cert.extensions.empty())
				s << "\t\t\t\t(empty)\n";
			else for (auto& ext: cert.extensions)
					ext->print(s, 4);
		}
	}
}

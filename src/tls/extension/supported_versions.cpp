#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {


	void supported_versions::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "supported_version:\n";
		for (auto& v: versions)
			s << std::string(level + 1, '\t') << v << "\n";
	}

	std::string supported_versions::build_() const {
		std::string msg;
		switch (message_type) {
			case msg_type_t::client_hello: {
				uint8_t ver_size = versions.size() * sizeof(protocol_version_t);
				msg.reserve(ver_size);
				//	versions.size
				msg.push_back(static_cast<char>(ver_size));
				//	versions.payload
				for (auto& ver: versions)
					reverse_write(msg, ver);
				break;
			}
			case msg_type_t::server_hello: {
				//	selected_version
				reverse_write(msg, versions.front());
				break;
			}
		}
		return msg;
	}

	supported_versions::supported_versions(std::string_view source, context& context)
			: extension(ext_type_t::supported_versions) {
		protocol_version_t ver;
		auto ptr = source.begin();
		switch (context.endpoint_type) {
			case context::endpoint_type_t::client: {
				message_type = msg_type_t::server_hello;
				//	selected_version
				reverse_read(ptr, ver);
				versions.push_back(ver);
				break;
			}
			case context::endpoint_type_t::server: {
				message_type = msg_type_t::client_hello;
				//	versions
				//		.size
				uint8_t versions_size;
				reverse_read(ptr, versions_size);
				//		.data
				while (versions_size) {
					reverse_read(ptr, ver);
					versions.push_back(ver);
					versions_size -= sizeof ver;
				}
				break;
			}
		}
	}

	supported_versions::supported_versions(const context& context)
			: extension(ext_type_t::supported_versions) {
		if (context.endpoint_version < protocol_version_t::TLS1_3)
			throw std::exception();
		switch (context.endpoint_type) {
			case context::endpoint_type_t::server:
				message_type = msg_type_t::server_hello;
				break;
			case context::endpoint_type_t::client:
				message_type = msg_type_t::client_hello;
				break;
			default:
				throw std::exception();
		}
		versions.push_back(context.endpoint_version);
	}
}

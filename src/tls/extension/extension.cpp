#include "tls-extension/extension.h"

#include "tls-record/alert.h"
#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	std::string extension::build() const {
		const auto data = build_();
		const uint16_t size = data.size();

		std::string msg;
		reverse_write(msg, extension_type);
		reverse_write(msg, size);
		msg += data;
		return msg;
	}

	extension* extension::parse(context& context, std::string_view::const_iterator& ptr, record& record) {
		ext_type_t ext_type;
		ext_data_size_t ext_size;
		reverse_read(ptr, ext_type);
		reverse_read(ptr, ext_size);
		const std::string_view ext_data{ptr, ptr + ext_size};
		ptr += ext_size;

		switch (ext_type) {
			case ext_type_t::server_name:
				return new server_name(ext_data);
			case ext_type_t::supported_versions:
				return new supported_versions(ext_data, context);
			case ext_type_t::key_share:
				return new key_share(
					ext_data,
					typeid(record) == typeid(server_hello) && dynamic_cast<server_hello&>(record).
					is_hello_retry_request,
					context);
			case ext_type_t::alpn:
				return new alpn(ext_data);
			default:
				return nullptr;
		}
	}

	std::ostream& operator<<(std::ostream& s, const extension& ext) {
		ext.print(s, 0);
		return s;
	}

	extension::extension(const ext_type_t t)
		: extension_type(t) {
	}
}

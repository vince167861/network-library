#include "tls-extension/extension.h"

#include "internal/utils.h"

namespace leaf::network::tls {

	std::expected<std::pair<ext_type_t, std::unique_ptr<extension_base>>, std::string>
	parse_extension(byte_string_view& __s, const extension_holder_t __ht) {
		auto it = __s.begin();
		const auto ext_type = read<ext_type_t>(std::endian::big, it);
		const auto ext_size = read<ext_data_size_t>(std::endian::big, it);
		if (sizeof(ext_type_t) + sizeof(ext_data_size_t) + ext_size > __s.size())
			return std::unexpected("incomplete extension");
		__s.remove_prefix(ext_size + sizeof(ext_type_t) + sizeof(ext_data_size_t));
		byte_string_view __d(it, ext_size);
		std::unique_ptr<extension_base> ptr;
		switch (ext_type) {
			case ext_type_t::supported_versions:
				ptr = std::make_unique<supported_versions>(__ht, __d);
				break;
			case ext_type_t::key_share:
				ptr = std::make_unique<key_share>(__ht, __d);
				break;
			case ext_type_t::supported_groups:
				ptr = std::make_unique<supported_groups>(__d);
				break;
			case ext_type_t::signature_algorithms:
				ptr = std::make_unique<signature_algorithms>(__d);
				break;
			case ext_type_t::psk_key_exchange_modes:
				ptr = std::make_unique<psk_key_exchange_modes>(__d);
				break;
			case ext_type_t::server_name:
				ptr = std::make_unique<server_name>(__d);
				break;
			/* case ext_type_t::renegotiation_info:
				return std::make_unique<renegotiation_info>(__d); */
			case ext_type_t::session_ticket:
				ptr = std::make_unique<session_ticket>(__d);
				break;
			case ext_type_t::record_size_limit:
				ptr = std::make_unique<record_size_limit>(__d);
				break;
			case ext_type_t::alpn:
				ptr = std::make_unique<alpn>(__d);
				break;
			default:
				ptr = std::make_unique<raw_extension>(ext_type, __d);
		}
		return {{ext_type, std::move(ptr)}};
	}

	raw_extension::raw_extension(const ext_type_t type, const byte_string_view data)
			: type(type), data(data) {
	}

	void raw_extension::format(std::format_context::iterator& __it, const std::size_t indent) const {
		__it = std::fill_n(__it, indent, '\t');
		__it = std::format_to(__it, "{} (raw extension, size={})", type, data.size());
	}

	raw_extension::operator byte_string() const {
		byte_string str;
		write(std::endian::big, str, type);
		write(std::endian::big, str, data.size(), 2);
		return str + data;
	}
}

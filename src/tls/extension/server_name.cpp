#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	server_name::server_name(std::initializer_list<std::pair<name_type_t, std::string>> list)
		: server_name_list(list) {
	}

	server_name::server_name(const byte_string_view source) {
		auto ptr = source.begin();
		const auto snl_size = read<std::uint16_t>(std::endian::big, ptr);
		auto available = std::distance(ptr, source.end());
		if (available < snl_size)
			throw alert::decode_error_early_end_of_data("server_name_list.size", available, snl_size);
		while (ptr != source.end()) switch (const auto t = read<name_type_t>(std::endian::big, ptr)) {
			case name_type_t::host_name: {
				const auto _L = read_bytestring(ptr, read<std::uint16_t>(std::endian::big, ptr));
				server_name_list.emplace_back(t, reinterpret_cast<const std::string&>(_L));
				break;
			}
		}
	}

	void server_name::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("server_name:", it).out;
		for (auto& [type, value]: server_name_list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level, '\t');
			it = std::format_to(it, "{:#x}: {}", static_cast<std::uint8_t>(type), value);
		}
	}

	server_name::operator byte_string() const {
		byte_string list_str;
		for (auto& [type, value]: server_name_list) {
			write(std::endian::big, list_str, type);
			switch (type) {
				case name_type_t::host_name:
					write(std::endian::big, list_str, value.size(), 2);
					list_str += reinterpret_cast<const byte_string&>(value);
					break;
			}
		}
		byte_string data;
		write(std::endian::big, data, list_str.size(), 2);
		byte_string out;
		write(std::endian::big, out, ext_type_t::server_name);
		write<ext_data_size_t>(std::endian::big, out, data.size() + list_str.size());
		return out + data + list_str;
	}
}

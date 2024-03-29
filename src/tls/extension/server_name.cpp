#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	server_name::server_name(const std::initializer_list<std::pair<name_type_t, std::string>> list)
		: server_name_list(list) {
	}

	server_name::server_name(const byte_string_view __s) {
		auto it = __s.begin();
		const auto __size = read<std::uint16_t>(std::endian::big, it);
		const auto end = std::next(it, __size);
		if (end > __s.end())
			throw alert::decode_error("incomplete ServerName");
		while (it != end) switch (const auto t = read<name_type_t>(std::endian::big, it)) {
			case name_type_t::host_name: {
				const auto _L = read_bytestring(it, read<std::uint16_t>(std::endian::big, it));
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

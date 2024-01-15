#include "tls-extension/extension.h"

#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	server_name::server_name(std::initializer_list<std::pair<name_type_t, std::string>> list)
		: server_name_list(list) {
	}

	server_name::server_name(std::string_view source) {
		auto ptr = source.begin();
		uint16_t snl_size;
		reverse_read(ptr, snl_size);
		auto available = std::distance(ptr, source.end());
		if (available < snl_size)
			throw alert::decode_error_early_end_of_data("server_name_list.size", available, snl_size);
		while (ptr != source.end()) {
			name_type_t t;
			reverse_read(ptr, t);
			switch (t) {
				case name_type_t::host_name: {
					uint16_t size;
					reverse_read(ptr, size);
					server_name_list.emplace_back(t, std::string{ptr, ptr + size});
					ptr += size;
				}
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

	server_name::operator raw_extension() const {
		std::string list_str;
		for (auto& [type, value]: server_name_list) {
			reverse_write(list_str, type);
			switch (type) {
				case name_type_t::host_name:
					reverse_write(list_str, value.size(), 2);
				list_str += value;
				break;
			}
		}
		std::string data;
		reverse_write(data, list_str.size(), 2);
		return {ext_type_t::server_name, std::move(data)};
	}
}

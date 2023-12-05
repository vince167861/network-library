#include "tls-extension/extension.h"

#include "tls-record/alert.h"
#include "utils.h"


namespace leaf::network::tls {

	server_name::server_name(std::initializer_list<std::pair<name_type_t, std::string>> list)
		: extension(ext_type_t::server_name), server_name_list(list) {
	}

	std::string server_name::build_() const {
		std::string msg;
		for (auto& [type, value]: server_name_list) {
			reverse_write(msg, type);
			switch (type) {
				case name_type_t::host_name: {
					uint16_t h_size = value.size();
					reverse_write(msg, h_size);
					msg += value;
				}
			}
		}
		uint16_t snl_size = msg.size();
		std::string ret;
		reverse_write(ret, snl_size);
		return std::move(ret) + std::move(msg);
	}

	void server_name::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "server_name: \n";
		for (auto& [type, value]: server_name_list)
			s << std::string(level + 1, '\t') << "0x" << std::hex << std::setfill('0') << static_cast<uint32_t>(type) <<
					": " << value << '\n';
	}

	server_name::server_name(std::string_view source)
		: extension(ext_type_t::server_name) {
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
}

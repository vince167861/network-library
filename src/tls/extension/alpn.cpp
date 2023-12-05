#include <utility>

#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	alpn::alpn(std::list<std::string> protocols)
		: extension(ext_type_t::alpn), protocol_name_list(std::move(protocols)) {
	}

	alpn::alpn(const std::string_view source)
		: extension(ext_type_t::alpn) {
		auto ptr = source.begin();
		uint16_t size;
		reverse_read(ptr, size);
		while (ptr != source.end()) {
			uint8_t name_size;
			reverse_read(ptr, name_size);
			auto begin = ptr;
			std::advance(ptr, name_size);
			protocol_name_list.emplace_back(begin, ptr);
		}
	}

	std::string alpn::build_() const {
		std::string list_string;
		for (auto& p: protocol_name_list) {
			reverse_write(list_string, p.size(), 1);
			list_string += p;
		}
		std::string ret;
		reverse_write(ret, list_string.size(), 2);
		ret += list_string;
		return ret;
	}

	void alpn::print(std::ostream& s, const std::size_t level) const {
		s << std::string(level, '\t') << "ALPN:\n";
		for (auto& p: protocol_name_list)
			s << std::string(level + 1, '\t') << p << '\n';
	}
}

#include <utility>

#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	alpn::alpn(std::list<std::string> protocols)
		: protocol_name_list(std::move(protocols)) {
	}

	alpn::alpn(const std::string_view source) {
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

	void alpn::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("ALPN:", it).out;
		if (protocol_name_list.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& p: protocol_name_list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::ranges::copy(p, it).out;
		}
	}

	alpn::operator raw_extension() const {
		std::string list_str;
		for (auto& p: protocol_name_list) {
			reverse_write(list_str, p.size(), 1);
			list_str += p;
		}
		std::string data;
		reverse_write(data, list_str.size(), 2);
		data += list_str;
		return {ext_type_t::alpn, std::move(data)};
	}
}

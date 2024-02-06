#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	alpn::alpn(std::list<std::string> protocols)
		: protocol_name_list(std::move(protocols)) {
	}

	alpn::alpn(const std::string_view source) {
		if (source.empty())
			return;
		auto ptr = source.begin();
		auto size = read<std::uint16_t>(std::endian::big, ptr);
		while (ptr != source.end())
			protocol_name_list.push_back(read_bytestring(ptr, read<std::uint8_t>(std::endian::big, ptr)));
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
			write(std::endian::big, list_str, p.size(), 1);
			list_str += p;
		}
		std::string data;
		write(std::endian::big, data, list_str.size(), 2);
		data += list_str;
		return {ext_type_t::alpn, std::move(data)};
	}
}

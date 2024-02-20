#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	alpn::alpn(std::list<std::string> protocols)
			: protocol_name_list(std::move(protocols)) {
	}

	alpn::alpn(const byte_string_view source) {
		if (source.empty())
			return;
		auto it = source.begin();
		auto size = read<std::uint16_t>(std::endian::big, it);
		const auto end = std::next(it, size);
		if (end > source.end())
			throw std::runtime_error("incomplete ALPN extension");
		while (it != end) {
			const auto _L = read_bytestring(it, read<std::uint8_t>(std::endian::big, it));
			protocol_name_list.push_back(reinterpret_cast<const std::string&>(_L));
		}
	}

	void alpn::format(std::format_context::iterator& it, const std::size_t level) const {
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

	alpn::operator byte_string() const {
		byte_string __lstr;
		for (auto& p: protocol_name_list) {
			write(std::endian::big, __lstr, p.size(), 1);
			__lstr += reinterpret_cast<const byte_string&>(p);
		}
		byte_string data;
		write(std::endian::big, data, __lstr.size(), 2);
		byte_string out;
		write(std::endian::big, out, ext_type_t::alpn);
		write<ext_data_size_t>(std::endian::big, out, data.size() + __lstr.size());
		return out + data + __lstr;
	}
}

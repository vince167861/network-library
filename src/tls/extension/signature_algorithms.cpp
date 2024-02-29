#include "tls-extension/extension.h"
#include "internal/utils.h"

#define EXT_NAME "SignatureAlgorithms"

namespace leaf::network::tls {

	signature_algorithms::signature_algorithms(std::initializer_list<signature_scheme_t> list)
			: list(list) {
	}

	void signature_algorithms::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("signature_algorithms:", it).out;
		for (auto& g: list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", g);
		}
	}

	signature_algorithms::operator byte_string() const {
		if (list.empty())
			throw std::runtime_error(EXT_NAME " requires at least one signature scheme.");
		byte_string data;
		write(std::endian::big, data, list.size() * sizeof(signature_scheme_t), 2);
		for (auto& s: list)
			write(std::endian::big, data, s);
		byte_string out;
		write(std::endian::big, out, ext_type_t::signature_algorithms);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}

	signature_algorithms::signature_algorithms(const byte_string_view __s) {
		auto it = __s.begin();
		const auto __size = read<std::uint16_t>(std::endian::big, it);
		const auto __end = std::next(it, __size);
		if (__end > __s.end())
			throw std::runtime_error("incomplete " EXT_NAME);
		while (it < __end)
			list.push_back(read<signature_scheme_t>(std::endian::big, it));
	}
}

#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	record_size_limit::record_size_limit(uint16_t l)
			: limit(l) {
	}

	void record_size_limit::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::format_to(it, "record_size_limit: {}", limit);
	}

	record_size_limit::operator byte_string() const {
		byte_string data;
		write(std::endian::big, data, limit);
		byte_string out;
		write(std::endian::big, out, ext_type_t::record_size_limit);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}

	record_size_limit::record_size_limit(const byte_string_view __s) {
		auto it = __s.begin();
		read(std::endian::big, limit, it);
	}
}

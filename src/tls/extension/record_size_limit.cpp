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

	record_size_limit::operator raw_extension() const {
		std::string data;
		write(std::endian::big, data, limit);
		return {ext_type_t::record_size_limit, std::move(data)};
	}
}

#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	signature_algorithms::signature_algorithms(std::initializer_list<signature_scheme_t> list)
		: list(list) {
	}

	void signature_algorithms::format(std::format_context::iterator& it, std::size_t level) const {
		using std::literals::operator ""sv;
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("signature_algorithms:"sv, it).out;
		for (auto& g: list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", g);
		}
	}

	signature_algorithms::operator raw_extension() const {
		if (list.empty())
			throw std::runtime_error{"SignatureAlgorithms requires at least one signature scheme."};
		std::string data;
		reverse_write(data, list.size() * sizeof(signature_scheme_t), 2);
		for (auto& s: list)
			reverse_write(data, s);
		return {ext_type_t::signature_algorithms, std::move(data)};
	}
}

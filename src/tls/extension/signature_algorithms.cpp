#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	void signature_algorithms::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "signature_algorithms: \n";
		for (auto& g: list)
			s << std::string(level + 1, '\t') << g << '\n';
	}

	std::string signature_algorithms::build_() const {
		if (list.empty())
			throw std::exception{};
		std::string data;
		uint16_t size = list.size() * sizeof(signature_scheme_t);
		reverse_write(data, size);
		for (auto& s: list)
			reverse_write(data, s);
		return data;
	}

	signature_algorithms::signature_algorithms(std::initializer_list<signature_scheme_t> list)
			: extension(ext_type_t::signature_algorithms), list(list) {
	}
}

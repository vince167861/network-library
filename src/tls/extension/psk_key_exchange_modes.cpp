#include "tls-extension/extension.h"
#include "utils.h"

namespace leaf::network::tls {

	psk_key_exchange_modes::psk_key_exchange_modes(const std::initializer_list<psk_key_exchange_mode_t> list)
		: modes(list) {
	}

	void psk_key_exchange_modes::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("psk_key_exchange_modes:", it).out;
		for (auto v: modes) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", v);
		}
	}

	psk_key_exchange_modes::operator raw_extension() const {
		std::string data;
		data.push_back(static_cast<char>(modes.size()));
		for (auto mode: modes)
			data.push_back(static_cast<char>(mode));
		return {ext_type_t::psk_key_exchange_modes, std::move(data)};
	}
}

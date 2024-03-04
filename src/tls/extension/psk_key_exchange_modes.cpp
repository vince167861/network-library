#include "tls-extension/extension.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	psk_key_exchange_modes::psk_key_exchange_modes(const std::initializer_list<psk_key_exchange_mode_t> list)
			: modes(list) {
	}

	psk_key_exchange_modes::psk_key_exchange_modes(const byte_string_view __s) {
		auto it = __s.begin();
		const auto __size = read<std::uint8_t>(std::endian::big, it);
		const auto end = std::next(it, __size);
		if (end > __s.end())
			throw std::runtime_error("incomplete PskKeyExchangeModes");
		while (it != end)
			modes.push_back(read<psk_key_exchange_mode_t>(std::endian::big, it));
	}

	psk_key_exchange_modes::operator byte_string() const {
		byte_string data;
		data.push_back(static_cast<std::uint8_t>(modes.size()));
		for (auto mode: modes)
			data.push_back(static_cast<std::uint8_t>(mode));
		byte_string out;
		write(std::endian::big, out, ext_type_t::psk_key_exchange_modes);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}

	void psk_key_exchange_modes::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("psk_key_exchange_modes:", it).out;
		for (const auto v: modes) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", v);
		}
	}
}

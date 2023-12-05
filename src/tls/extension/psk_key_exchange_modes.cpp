#include "tls-extension/extension.h"

namespace leaf::network::tls {

	psk_key_exchange_modes::psk_key_exchange_modes(const std::initializer_list<psk_key_exchange_mode_t> list)
		: extension(ext_type_t::psk_key_exchange_modes), modes(list) {
	}

	std::string psk_key_exchange_modes::build_() const {
		std::string msg;
		uint8_t size = modes.size();
		msg.push_back(static_cast<char>(size));
		for (auto mode: modes)
			msg.push_back(static_cast<char>(mode));
		return msg;
	}

	void psk_key_exchange_modes::print(std::ostream& s, const std::size_t level) const {
		s << std::string(level, '\t') << "psk_key_exchange_modes:\n";
		for (auto v: modes)
			s << std::string(level + 1, '\t') << "0x" << std::hex << static_cast<uint32_t>(v) << '\n';
	}
}

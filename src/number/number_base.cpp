#include "include\number\fixed.h"

namespace leaf {

	std::string number_base::to_bytes() const {
		std::string ret;
		auto top_bytes = (bits() / 8 + (bits() % 8 ? 1 : 0)) % unit_bytes;
		if (!top_bytes) top_bytes = unit_bytes;
		for (std::size_t i = 0; i < data_units(); ++i) {
			auto bytes = i == 0 ? top_bytes : unit_bytes;
			for (std::size_t j = 0; j < bytes; ++j)
				ret.push_back(static_cast<char>((*this)[data_units() - i - 1] >> (bytes - j - 1) * 8));
		}
		return ret;
	}

	std::string number_base::to_little_endian_bytes() const {
		std::string ret;
		auto top_bytes = (bits() / 8 + (bits() % 8 ? 1 : 0)) % unit_bytes;
		auto units = data_units();
		if (!top_bytes) top_bytes = unit_bytes;
		for (std::size_t i = 0; i < units; ++i) {
			auto bytes = i == units - 1 ? top_bytes : unit_bytes;
			for (std::size_t j = 0; j < bytes; ++j)
				ret.push_back(static_cast<char>((*this)[i] >> j * 8));
		}
		return ret;
	}

	std::string number_base::to_string() const {
		std::stringstream s;
		bool first = true;
		for (std::size_t i = 0; i < data_units(); ++i) {
			auto val = (*this)[data_units() - i - 1];
			if (first) {
				if (val > 0) {
					first = false;
					s << std::hex << val;
				}
			} else
				s << std::hex << std::setw(unit_bytes * 2) << std::setfill('0') << val;
		}
		if (first)
			s << "0";
		return s.str();
	}

	std::ostream& operator<<(std::ostream& s, const number_base& number) {
		bool first = true;
		for (std::size_t i = 0; i < number.data_units(); ++i) {
			auto val = number[number.data_units() - i - 1];
			if (first) {
				if (val > 0) {
					first = false;
					s << "0x" << std::hex << val;
				}
			} else
				s << std::hex << std::setw(number_base::unit_bytes * 2) << std::setfill('0') << val;
		}
		if (first)
			s << "0";
		return s;
	}
}

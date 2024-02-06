#include "number/fixed.h"
#include "utils.h"

#include <format>

namespace leaf {

	std::string number_base::to_bytestring(std::endian endian) const {
		if (!bits())
			return "";
		std::string str;
		bool big_endian = endian == std::endian::big;
		const auto top_bytes = (bits() / 8 + (bits() % 8 ? 1 : 0)) % unit_bytes;
		if (big_endian)
			write(std::endian::big, str, operator[](data_units() - 1), top_bytes ? top_bytes : unit_bytes);
		for (std::size_t i = data_units() - 1; i > 0; --i)
			write(endian, str, operator[](big_endian ? i - 1 : data_units() - 1 - i));
		if (!big_endian)
			write(std::endian::little, str, operator[](data_units() - 1), top_bytes ? top_bytes : unit_bytes);
		return str;
	}

	std::string number_base::to_string() const {
		if (!bits())
			return "0";
		std::string str;
		for (std::size_t i = data_units() - 1; i > 0; --i) {
			const auto val = operator[](i);
			if (str.empty() && val)
				str = std::format("{:x}", val);
			else
				str += std::format("{:02x}", val);
		}
		return str.empty() ? "0" : str;
	}
}

#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	std::optional<raw_extension> parse_extension(std::string_view& source) {
		auto it = source.begin();
		const auto ext_type = read<ext_type_t>(std::endian::big, it);
		const auto ext_size = read<ext_data_size_t>(std::endian::big, it);
		if (ext_size > source.size() - sizeof(ext_type_t) - sizeof(ext_data_size_t))
			return {};
		source.remove_prefix(ext_size + sizeof(ext_type_t) + sizeof(ext_data_size_t));
		return {raw_extension{ext_type, {it, std::next(it, ext_size)}}};
	}

	raw_extension::raw_extension(ext_type_t type, std::string data)
		: type(type), data(data) {
	}

	std::string raw_extension::to_bytestring(std::endian) const {
		std::string str;
		write(std::endian::big, str, type);
		write(std::endian::big, str, data.size(), 2);
		return str + data;
	}

	std::string extension_base::to_bytestring(std::endian endian) const {
		return raw_extension{*this}.to_bytestring(endian);
	}
}

#include "tls-extension/extension.h"

#include "tls-record/alert.h"
#include "tls-handshake/handshake.h"
#include "utils.h"

namespace leaf::network::tls {

	std::optional<raw_extension> parse_extension(std::string_view& source) {
		ext_type_t ext_type;
		ext_data_size_t ext_size;
		auto it = source.begin();
		reverse_read(it, ext_type);
		reverse_read(it, ext_size);
		if (ext_size > source.size() - sizeof(ext_type_t) - sizeof(ext_data_size_t))
			return {};
		source.remove_prefix(ext_size + sizeof(ext_type_t) + sizeof(ext_data_size_t));
		return {raw_extension{ext_type, {it, std::next(it, ext_size)}}};
	}

	raw_extension::raw_extension(ext_type_t type, std::string data)
		: type(type), data(data) {
	}

	std::string raw_extension::to_bytestring() const {
		std::string str;
		reverse_write(str, type);
		reverse_write(str, data.size(), 2);
		return str + data;
	}

	std::string extension_base::to_bytestring() const {
		return raw_extension{*this}.to_bytestring();
	}
}

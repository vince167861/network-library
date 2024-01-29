#include "tls-extension/extension.h"

#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	supported_groups::supported_groups(const context& context) {
		switch (context.endpoint_type) {
			case context::endpoint_type_t::client:
				message_type = msg_type_t::client_hello;
			break;
			case context::endpoint_type_t::server:
				message_type = msg_type_t::server_hello;
			break;
		}
		for (auto& m: context.managers)
			named_group_list.push_back(m->group);
	}

	supported_groups::supported_groups(std::string_view source, context& context) {
		switch (context.endpoint_type) {
			case context::endpoint_type_t::client:
				message_type = msg_type_t::server_hello;
			break;
			case context::endpoint_type_t::server:
				message_type = msg_type_t::client_hello;
			break;
		}
		auto ptr = source.begin();
		const auto ngl_size = read<std::uint16_t>(std::endian::big, ptr);
		if (std::distance(ptr, source.end()) < ngl_size)
			throw alert::decode_error_early_end_of_data("named_group_list.size", std::distance(ptr, source.end()), ngl_size);
		while (ptr != source.end())
			named_group_list.push_back(read<named_group_t>(std::endian::big, ptr));
	}

	void supported_groups::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("supported_groups: \n", it).out;
		if (named_group_list.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto g: named_group_list) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", g);
		}
	}

	supported_groups::operator raw_extension() const {
		std::string data;
		write(std::endian::big, data, named_group_list.size() * sizeof(named_group_t), 2);
		for (auto g: named_group_list)
			write(std::endian::big, data, g);
		return {ext_type_t::supported_groups, std::move(data)};
	}
}

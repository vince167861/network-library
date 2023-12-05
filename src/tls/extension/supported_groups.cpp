#include "tls-extension/extension.h"

#include "utils.h"
#include "tls-record/alert.h"

namespace leaf::network::tls {

	supported_groups::supported_groups(const context& context)
			: extension(ext_type_t::supported_groups) {
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

	std::string supported_groups::build_() const {
		std::string msg;
		//	named_group_list.size
		uint16_t D = named_group_list.size() * sizeof(named_group_t);
		reverse_write(msg, D);
		//	named_group_list.payload
		for (auto& g: named_group_list)
			reverse_write(msg, g);
		return msg;
	}

	void supported_groups::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "supported_groups: \n";
		if (named_group_list.empty())
			s << std::string(level + 1, '\t') << "(empty)\n";
		else
			for (auto g: named_group_list)
				s << std::string(level + 1, '\t') << g << '\n';
	}

	supported_groups::supported_groups(std::string_view source, context& context)
			: extension(ext_type_t::supported_groups) {
		switch (context.endpoint_type) {
			case context::endpoint_type_t::client:
				message_type = msg_type_t::server_hello;
			break;
			case context::endpoint_type_t::server:
				message_type = msg_type_t::client_hello;
			break;
		}
		auto ptr = source.begin();
		//	named_group_list
		//		.size
		uint16_t ngl_size;
		reverse_read(ptr, ngl_size);
		if (std::distance(ptr, source.end()) < ngl_size)
			throw alert::decode_error_early_end_of_data("named_group_list.size", std::distance(ptr, source.end()), ngl_size);
		//		.payload
		while (ptr != source.end()) {
			named_group_t ng;
			reverse_read(ptr, ng);
			named_group_list.push_back(ng);
		}
	}
}

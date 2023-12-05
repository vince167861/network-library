#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	std::string key_share::build_() const {
		std::string msg;
		switch (message_type) {
			case msg_type_t::client_hello: {
				std::string client_shares;
				for (auto& [group, key]: shares) {
					uint16_t k_size = key.size();
					//	key_share_entry
					//		.group
					reverse_write(client_shares, group);
					//		.public_key
					reverse_write(client_shares, k_size);
					client_shares += key;
				}
				//	client_shares
				uint16_t s_size = client_shares.size();
				reverse_write(msg, s_size);
				msg += client_shares;
				break;
			}
			case msg_type_t::hello_retry_request: {
				//	selected_group
				reverse_write(msg, shares.front().first);
				break;
			}
			case msg_type_t::server_hello: {
				//	server_share
				//		.group
				reverse_write(msg, shares.front().first);
				//		.public_key_
				//			.size
				uint16_t k_size = shares.front().second.size();
				reverse_write(msg, k_size);
				//			.payload
				msg += shares.front().second;
				break;
			}
		}
		return msg;
	}

	key_share::key_share(const context& context)
			: extension(ext_type_t::key_share) {
		switch (context.endpoint_type) {
			case context::endpoint_type_t::server:
				message_type = msg_type_t::server_hello;
				break;
			case context::endpoint_type_t::client:
				message_type = msg_type_t::client_hello;
				break;
		}
		for (auto& m: context.managers)
			if (m->key_ready())
				shares.emplace_back(m->group, m->public_key());
	}

	key_share::key_share(std::string_view source, bool is_hello_retry_request, context& context)
			: extension(ext_type_t::key_share) {
		auto ptr = source.begin();
		switch (context.endpoint_type) {
			case context::endpoint_type_t::server: {
				message_type = msg_type_t::client_hello;
				//	client_shares
				uint16_t cs_size;
				reverse_read(ptr, cs_size);
				if (std::distance(ptr, source.end()) < cs_size)
					throw alert::decode_error_early_end_of_data("client_shares.size", std::distance(ptr, source.end()), cs_size);
				//		.payload
				while (cs_size) {
					named_group_t ng;
					//	key_share_entry
					//		.group
					reverse_read(ptr, ng);
					//		.public_key
					uint16_t ke_size;
					//			.size
					reverse_read(ptr, ke_size);
					//			.payload
					shares.emplace_back(ng, std::string{ptr, ptr + ke_size});
					ptr += ke_size;
					cs_size -= ke_size;
				}
				break;
			}
			case context::endpoint_type_t::client: {
				if (is_hello_retry_request) {
					message_type = msg_type_t::hello_retry_request;
					named_group_t selected;
					reverse_read(ptr, selected);
					shares.emplace_back(selected, "");
				} else {
					message_type = msg_type_t::server_hello;
					named_group_t ng;
					//	server_share
					//		.group
					reverse_read(ptr, ng);
					//		.public_key
					uint16_t ke_size;
					//			.size
					reverse_read(ptr, ke_size);
					if (std::distance(ptr, source.end()) < ke_size)
						throw alert::decode_error_early_end_of_data("server_share.public_key.size", std::distance(ptr, source.end()), ke_size);
					//			.payload
					shares.emplace_back(ng, std::string{ptr, ptr + ke_size});
				}
				break;
			}
		}
	}

	void key_share::print(std::ostream& s, std::size_t level) const {
		s << std::string(level, '\t') << "key_share:\n";
		if (shares.empty())
			s << std::string(level + 1, '\t') << "(empty)\n";
		else for (auto& [group, key]: shares) {
			s << std::string(level + 1, '\t') << group;
			if (!key.empty())
				s << ": " << var_unsigned::from_bytes(key).to_string();
			s << '\n';
		}
	}
}

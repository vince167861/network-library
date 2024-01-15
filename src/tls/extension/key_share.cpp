#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	key_share::key_share(const context& context) {
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

	key_share::key_share(std::string_view source, bool is_hello_retry_request, context& context) {
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

	void key_share::format(std::format_context::iterator& it, std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("key_share:", it).out;
		if (shares.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& [group, key]: shares) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", group);
			if (!key.empty())
				it = std::format_to(it, ": {}", var_unsigned::from_bytes(key).to_string());
		}
	}

	key_share::operator raw_extension() const {
		std::string data;
		switch (message_type) {
			case msg_type_t::client_hello: {
				std::string client_shares;
				for (auto& [group, key]: shares) {
					reverse_write(client_shares, group);
					reverse_write(client_shares, key.size(), 2);
					client_shares += key;
				}
				reverse_write(data, client_shares.size(), 2);
				data += client_shares;
				break;
			}
			case msg_type_t::hello_retry_request:
				reverse_write(data, shares.front().first);
				break;
			case msg_type_t::server_hello:
				reverse_write(data, shares.front().first);
				reverse_write(data, shares.front().second.size(), 2);
				data += shares.front().second;
				break;
		}
		return {ext_type_t::key_share, std::move(data)};
	}
}

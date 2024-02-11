#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "utils.h"

namespace leaf::network::tls {

	key_share::key_share(
			msg_type_t type, const std::map<named_group_t, std::unique_ptr<key_exchange_manager>>& managers)
			: message_type(type) {
		for (auto& [grp, mgr]: managers)
			shares.emplace(mgr->group, mgr->public_key());
	}

	key_share::key_share(msg_type_t type, std::map<named_group_t, std::string> shares)
			: message_type(type), shares(std::move(shares)) {
	}

	key_share::key_share(msg_type_t type, std::string_view source)
			: message_type(type) {
		auto ptr = source.begin();
		switch (type) {
			case msg_type_t::client_hello: {
				const auto cs_size = read<std::uint16_t>(std::endian::big, ptr);
				if (std::distance(ptr, source.end()) < cs_size)
					throw alert::decode_error_early_end_of_data("client_shares.size", std::distance(ptr, source.end()), cs_size);
				while (ptr != source.end()) {
					const auto ng = read<named_group_t>(std::endian::big, ptr);
					shares.emplace(ng, read_bytestring(ptr, read<std::uint16_t>(std::endian::big, ptr)));
				}
				return;
			}
			case msg_type_t::hello_retry_request: {
				shares.emplace(read<named_group_t>(std::endian::big, ptr), "");
				return;
			}
			case msg_type_t::server_hello: {
				const auto ng = read<named_group_t>(std::endian::big, ptr);
				const auto ke_size = read<std::uint16_t>(std::endian::big, ptr);
				if (std::distance(ptr, source.end()) < ke_size)
					throw alert::decode_error_early_end_of_data("server_share.public_key.size", std::distance(ptr, source.end()), ke_size);
				shares.emplace(ng, std::string{ptr, std::next(ptr, ke_size)});
				return;
			}
			default:
				throw std::runtime_error{"unexpected @ key_share::key_share(msg_type_t, std::string_view)"};
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
				it = std::format_to(it, ": {}", big_unsigned(key).to_string());
		}
	}

	key_share::operator raw_extension() const {
		std::string data;
		switch (message_type) {
			case msg_type_t::client_hello: {
				std::string client_shares;
				for (auto& [group, key]: shares) {
					write(std::endian::big, client_shares, group);
					write(std::endian::big, client_shares, key.size(), 2);
					client_shares += key;
				}
				write(std::endian::big, data, client_shares.size(), 2);
				data += client_shares;
				break;
			}
			case msg_type_t::hello_retry_request:
				write(std::endian::big, data, shares.begin()->first);
				break;
			case msg_type_t::server_hello:
				write(std::endian::big, data, shares.begin()->first);
				write(std::endian::big, data, shares.begin()->second.size(), 2);
				data += shares.begin()->second;
				break;
		}
		return {ext_type_t::key_share, std::move(data)};
	}
}

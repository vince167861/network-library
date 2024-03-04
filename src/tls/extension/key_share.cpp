#include "tls-extension/extension.h"
#include "tls-record/alert.h"
#include "internal/utils.h"

using namespace internal;

namespace network::tls {

	key_share::key_share(const extension_holder_t type, const std::map<named_group_t, std::unique_ptr<key_exchange_manager>>& managers)
			: holder_type(type) {
		for (auto& [grp, mgr]: managers)
			shares.emplace(mgr->group, mgr->public_key());
	}

	key_share::key_share(const extension_holder_t type, std::map<named_group_t, byte_string> shares)
			: holder_type(type), shares(std::move(shares)) {
	}

	key_share::key_share(const extension_holder_t type, const byte_string_view source)
			: holder_type(type) {
		auto it = source.begin();
		switch (type) {
			case extension_holder_t::client_hello: {
				const auto __size = read<std::uint16_t>(std::endian::big, it);
				const auto end = std::next(it, __size);
				if (end > source.end())
					throw alert::decode_error("incomplete KeyShare");
				while (it != end) {
					const auto ng = read<named_group_t>(std::endian::big, it);
					shares.emplace(ng, read_bytestring(it, read<std::uint16_t>(std::endian::big, it)));
				}
				return;
			}
			case extension_holder_t::hello_retry_request: {
				shares.emplace(read<named_group_t>(std::endian::big, it), byte_string());
				return;
			}
			case extension_holder_t::server_hello: {
				const auto __ng = read<named_group_t>(std::endian::big, it);
				const auto __size = read<std::uint16_t>(std::endian::big, it);
				const auto end = std::next(it, __size);
				if (end > source.end())
					throw alert::decode_error("incomplete KeyShare");
				shares.emplace(__ng, byte_string(it, end));
				return;
			}
			default:
				throw std::runtime_error("unexpected");
		}
	}

	void key_share::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("key_share:", it).out;
		if (shares.empty())
			it = std::ranges::copy(" (empty)", it).out;
		else for (auto& [group, key]: shares) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}: {}", group, key);
		}
	}

	key_share::operator byte_string() const {
		byte_string data;
		switch (holder_type) {
			case extension_holder_t::client_hello: {
				byte_string client_shares;
				for (auto& [group, key]: shares) {
					write(std::endian::big, client_shares, group);
					write(std::endian::big, client_shares, key.size(), 2);
					client_shares += key;
				}
				write(std::endian::big, data, client_shares.size(), 2);
				data += client_shares;
				break;
			}
			case extension_holder_t::hello_retry_request:
				write(std::endian::big, data, shares.begin()->first);
				break;
			case extension_holder_t::server_hello:
				write(std::endian::big, data, shares.begin()->first);
				write(std::endian::big, data, shares.begin()->second.size(), 2);
				data += shares.begin()->second;
				break;
			default:
				throw std::runtime_error("unexpected");
		}
		byte_string out;
		write(std::endian::big, out, ext_type_t::key_share);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}
}

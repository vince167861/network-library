#include "tls-extension/extension.h"
#include "utils.h"

namespace leaf::network::tls {

	supported_versions::supported_versions(const extension_holder_t type, const byte_string_view source)
			: holder_type(type) {
		auto it = source.begin();
		switch (holder_type) {
			case extension_holder_t::hello_retry_request:
			case extension_holder_t::server_hello: {
				const auto end = std::next(it, sizeof(protocol_version_t));
				if (end > source.end())
					throw std::runtime_error("incomplete SupportedVersions");
				versions.push_back(read<protocol_version_t>(std::endian::big, it));
				return;
			}
			case extension_holder_t::client_hello: {
				const auto end = std::next(it, read<std::uint8_t>(std::endian::big, it));
				if (end > source.end())
					throw std::runtime_error{"SupportedVersions.versions.[size]"};
				while (it != end)
					versions.push_back(read<protocol_version_t>(std::endian::big, it));
				return;
			}
			default:
				throw std::runtime_error("unexpected");
		}
	}

	supported_versions::supported_versions(extension_holder_t type, std::initializer_list<protocol_version_t> versions)
			: holder_type(type), versions(versions) {
	}

	void supported_versions::format(std::format_context::iterator& it, const std::size_t level) const {
		it = std::ranges::fill_n(it, level, '\t');
		it = std::ranges::copy("supported_version:", it).out;
		for (auto& v: versions) {
			*it++ = '\n';
			it = std::ranges::fill_n(it, level + 1, '\t');
			it = std::format_to(it, "{}", v);
		}
	}

	supported_versions::operator byte_string() const {
		byte_string data;
		switch (holder_type) {
			case extension_holder_t::client_hello: {
				const std::uint8_t ver_size = versions.size() * sizeof(protocol_version_t);
				data.reserve(ver_size + 1);
				data.push_back(static_cast<char>(ver_size));
				for (auto& ver: versions)
					write(std::endian::big, data, ver);
				break;
			}
			case extension_holder_t::hello_retry_request:
			case extension_holder_t::server_hello:
				write(std::endian::big, data, versions.front());
				break;
			default:
				throw std::runtime_error("unexpected");
		}
		byte_string out;
		write(std::endian::big, out, ext_type_t::supported_versions);
		write<ext_data_size_t>(std::endian::big, out, data.size());
		return out + data;
	}
}

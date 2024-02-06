#include "tls-extension/extension.h"

#include "utils.h"

namespace leaf::network::tls {

	supported_versions::supported_versions(msg_type_t type, std::string_view source)
		: message_type(type) {
		auto ptr = source.begin();
		switch (message_type) {
			case msg_type_t::server_hello:
				if (std::distance(ptr, source.end()) < sizeof(protocol_version_t))
					throw std::runtime_error{"SupportedVersions.versions.[size]"};
				versions.push_back(read<protocol_version_t>(std::endian::big, ptr));
				return;
			case msg_type_t::client_hello: {
				const auto end = std::next(ptr, read<std::uint8_t>(std::endian::big, ptr));
				if (end > source.end())
					throw std::runtime_error{"SupportedVersions.versions.[size]"};
				while (ptr != end)
					versions.push_back(read<protocol_version_t>(std::endian::big, ptr));
				return;
			}
		}
	}

	supported_versions::supported_versions(msg_type_t type, std::initializer_list<protocol_version_t> versions)
			: message_type(type), versions(versions) {
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

	supported_versions::operator raw_extension() const {
		std::string data;
		switch (message_type) {
			case msg_type_t::client_hello: {
				const std::uint8_t ver_size = versions.size() * sizeof(protocol_version_t);
				data.reserve(ver_size + 1);
				data.push_back(static_cast<char>(ver_size));
				for (auto& ver: versions)
					write(std::endian::big, data, ver);
				break;
			}
			case msg_type_t::server_hello:
				write(std::endian::big, data, versions.front());
				break;
		}
		return {ext_type_t::supported_versions, std::move(data)};
	}
}

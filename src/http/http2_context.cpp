#include "http2/context.h"

namespace leaf::network::http2 {

	void context::update_remote_config(const std::list<std::pair<settings_t, uint32_t>>& values) {
		for (auto& [s, v]: values)
			switch (s) {
				case settings_t::max_concurrent_stream:
					remote_config.max_concurrent_streams = v;
					break;
				case settings_t::header_table_size:
					remote_config.header_table_size = v;
			}
	}

	std::list<std::pair<settings_t, uint32_t>>
	context::pack_settings() const {
		return {
				{settings_t::max_concurrent_stream, local_config.max_concurrent_streams}
		};
	}

	uint32_t context::new_local_stream_id() {
		if (local_config.last_open_stream == 0)
			switch (endpoint_type) {
				case endpoint_type_t::client:
					local_config.last_open_stream = 1;
					break;
				case endpoint_type_t::server:
					local_config.last_open_stream = 2;
					break;
			}
		else
			local_config.last_open_stream += 2;
		return local_config.last_open_stream;
	}

	void context::new_remote_stream_id(const uint32_t new_stream_id) {
		if (remote_config.last_open_stream == 0)
			switch (endpoint_type) {
				case endpoint_type_t::client:
					remote_config.last_open_stream = 2;
				break;
				case endpoint_type_t::server:
					remote_config.last_open_stream = 1;
				break;
			}
		else
			remote_config.last_open_stream += 2;
		if (remote_config.last_open_stream != new_stream_id)
			throw std::exception{};
	}

	context::context(const endpoint_type_t t)
		: endpoint_type(t) {
	}
}

#pragma once

#include "http2/type.h"
#include "http2/header_packer.h"

#include <map>
#include <sstream>

namespace leaf::network::http2 {


	class context {

		/**
		 * Tuple content: [buffered content, available bytes]
		 */
		std::map<uint32_t, std::tuple<std::stringstream, uint32_t>> stream_buffer_;

	public:
		struct state_t {
			uint32_t max_concurrent_streams = 100;
			uint32_t last_open_stream = 0;
			uint32_t max_frame_size: 24 = 65535;
			uint32_t header_table_size = 4096;
		};

		const enum class endpoint_type_t: uint8_t {
			server, client
		} endpoint_type;

		state_t local_config, remote_config;

		header_packer local_packer, remote_packer;

		void update_remote_config(const std::list<std::pair<settings_t, uint32_t>>&);

		std::list<std::pair<settings_t, uint32_t>>
		pack_settings() const;

		uint32_t new_local_stream_id();

		void new_remote_stream_id(uint32_t);

		explicit context(endpoint_type_t);
	};
}

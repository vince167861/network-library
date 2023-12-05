#pragma once

#include "shared/stream.h"
#include "http2/header_packer.h"

#include <cstdint>
#include <list>
#include <string>

#include "frame.h"

namespace leaf::network::http2 {

	using header_list_t = std::list<std::pair<std::string, std::string>>;

	class message {
	public:
		header_list_t headers;

		bool header_only = false;

		std::string pending_field_block_fragments;

		std::string body;

		virtual std::list<std::shared_ptr<frame>> build(uint32_t stream_id, header_packer&, uint32_t max_frame_size) const = 0;

		virtual ~message() = default;
	};
}

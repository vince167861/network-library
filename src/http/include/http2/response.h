#pragma once

#include "http2/message.h"
#include "http2/request.h"

#include <future>

namespace leaf::network::http2 {

	class response final: public message {
	public:
		long status;

		request request;

		std::list<std::future<response>> pushed;

		response(const http2::request&);

		std::list<std::shared_ptr<frame>>
		build(uint32_t stream_id, header_packer&, uint32_t max_frame_size) const override;
	};
}

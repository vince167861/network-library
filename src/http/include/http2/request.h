#pragma once

#include "http/url.h"
#include "http2/header_packer.h"
#include "http2/message.h"

#include "frame.h"

namespace leaf::network::http2 {

	class request final: public message {
	public:
		std::string method;

		url request_url;

		request() = default;

		request(std::string method, url target, header_list_t headers = {});

		void from_push_promise(header_list_t headers);

		std::list<std::shared_ptr<frame>>
		build(uint32_t stream_id, header_packer&, uint32_t max_frame_size) const override;
	};
}

#pragma once

#include "http/url.h"
#include "http2/header_packer.h"
#include "http2/message.h"

namespace leaf::network::http2 {

	class request final: public message {
	public:
		std::string method;

		url request_url;

		request() = default;

		request(std::string method, url target, header_list_t headers = {});
	};
}

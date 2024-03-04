#pragma once
#include "basic_endpoint.h"
#include "basic_stream.h"
#include <memory>

namespace network {

	struct stream_endpoint: virtual stream, virtual basic_endpoint {
	};

	struct stream_client: virtual stream_endpoint, virtual basic_client {
	};

	struct stream_server: virtual basic_server {

		virtual std::unique_ptr<stream_endpoint> accept() = 0;
	};
}

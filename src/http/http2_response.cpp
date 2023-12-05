#include "http2/response.h"

namespace leaf::network::http2 {

	response::response(const http2::request& request)
		: request(request) {
	}

	std::list<std::shared_ptr<frame>> response::build(uint32_t stream_id, header_packer&, uint32_t max_frame_size) const {
		throw std::exception{};
	}
}

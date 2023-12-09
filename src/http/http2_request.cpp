#include "http2/request.h"

#include "http2/frame.h"
#include "utils.h"

namespace leaf::network::http2 {

	request::request(std::string method, url target, std::list<std::pair<std::string, std::string>> headers)
		: method(std::move(method)), request_url(std::move(target)) {
		this->headers = std::move(headers);
	}

}

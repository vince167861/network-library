#include "http/request.h"

#include <iostream>


namespace leaf::network::http {

	request::request(std::string method, url target, http_fields headers)
		: message{std::move(headers)}, method(std::move(method)), request_url(std::move(target)) {
	}

	void request::print(std::ostream& s) const {
		s << "Request " << method << ' ' << request_url.url_string() << '\n';
		for (auto& [key, value]: headers)
			s << '\t' << key << ": " << value << '\n';
		s << body << '\n';
	}
}

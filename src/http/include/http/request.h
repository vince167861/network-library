#pragma once

#include "message.h"
#include "url.h"

#include <string>


namespace leaf::network::http {

	class request final: public message {
	public:
		std::string method;

		url request_url;

		request() = default;

		request(std::string method, url, std::list<std::pair<std::string, std::string>> headers = {});

		void print(std::ostream&) const;
	};

} // leaf

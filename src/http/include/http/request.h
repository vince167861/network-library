#pragma once

#include "message.h"
#include "url.h"

#include <string>


namespace leaf::network::http {

	struct request final: message {

		std::string method;

		url request_url;

		std::string body;

		request() = default;

		request(std::string method, url, http_fields headers = {});

		void print(std::ostream&) const;
	};

}

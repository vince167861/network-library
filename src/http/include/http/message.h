#pragma once

#include <list>
#include <string>

namespace leaf::network::http {

	struct message {
		std::list<std::pair<std::string, std::string>> headers;

		std::string body;
	};

}

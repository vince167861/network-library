#pragma once

#include <map>
#include <string>

namespace leaf::network::http {

	class message {
	public:
		std::map<std::string, std::string> headers;
		std::string body;
	};

} // leaf

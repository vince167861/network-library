#pragma once

#include <list>
#include <string>

namespace leaf::network::http2 {

	using header_list_t = std::list<std::pair<std::string, std::string>>;

	class message {
	public:
		header_list_t headers;

		std::string body;

		virtual ~message() = default;
	};
}

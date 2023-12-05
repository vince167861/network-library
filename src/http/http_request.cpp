#include "http/request.h"

#include "utils.h"
#include <list>
#include <sstream>

namespace leaf::network::http {

	request& request::handler(event_handler_t&& handler) {
		event_handlers.push_back(handler);
		return *this;
	}

	void request::trigger(const event_argument_t& arg) const {
		for (auto& handler: event_handlers)
			handler(*this, arg);
	}

	std::string request::build() const {
		std::list<std::pair<std::string, std::string>> headers_copy{headers.begin(), headers.end()};
		headers_copy.remove_if([](const auto& p){
			return ignore_case_equal(p.first, "Host");});
		headers_copy.emplace_front("Host", target_url.host);
		if (!body.empty())
			headers_copy.emplace_back("content-length", std::to_string(body.length()));
		std::stringstream request;
		request << method << ' ' << (target_url.path.empty() ? "/" : target_url.path);
		if (!target_url.query.empty())
			request << '?' << to_url_encoded(target_url.query);
		request << " HTTP/1.1\r\n";
		for (auto& [field, value]: headers_copy)
			request << field << ": " << value << "\r\n";
		request << "\r\n" << body;
		return request.str();
	}

}

#pragma once

#include "message.h"
#include "response.h"
#include "url.h"

#include <utility>
#include <functional>
#include <list>
#include <string>
#include <variant>


namespace leaf::network::http {

	class request: public message {
	public:
		enum class error_t {
			unknown_port, connect_failed
		};

		using event_argument_t = std::variant<response, std::pair<std::string, std::string>, error_t>;

		using event_handler_t = std::function<void(const request&, const event_argument_t&)>;

	private:
		std::list<event_handler_t> event_handlers;

	public:
		std::string method;

		url target_url;

		request(std::string method, url target, std::map<std::string, std::string> headers = {})
			: message{.headers = std::move(headers)}, method(std::move(method)), target_url(std::move(target)) {
		}

		request& handler(event_handler_t&&);

		void trigger(const event_argument_t&) const;

		[[nodiscard]] std::string build() const;
	};

} // leaf

#pragma once

#include "http/message.h"

#include <optional>
#include <coroutine>
#include <queue>

namespace leaf::network::http {

	struct event {

		std::string event_type;

		std::string data;

		std::optional<std::string> id;
	};


	struct event_source_promise;


	struct event_source: message, std::coroutine_handle<event_source_promise> {

		using promise_type = event_source_promise;

		unsigned retry_time = 1000;

		std::string last_event_id;

		event_source(const std::coroutine_handle<event_source_promise>& handle)
			: message(), std::coroutine_handle<event_source_promise>(handle) {}

		std::optional<event> await_next_event();
	};


	struct event_source_promise {

		std::optional<event> received;

		void return_void() {}

		std::suspend_always yield_value(event event) {
			received = std::move(event);
			return {};
		}

		event_source get_return_object() {
			return {event_source::from_promise(*this)};
		}

		std::suspend_always initial_suspend() {
			return {};
		}

		std::suspend_always final_suspend() noexcept {
			return {};
		}

		void unhandled_exception() {
			throw std::current_exception();
		}
	};
}

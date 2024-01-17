#include "http/event_stream.h"

namespace leaf::network::http {

	std::optional<event> event_source::await_next_event() {
		if (this->done())
			return {};
		this->resume();
		std::optional<event> event;
		std::swap(event, promise().received);
		return event;
	}
}

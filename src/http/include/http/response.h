#pragma once

#include "message.h"
#include "shared/client.h"

namespace leaf::network::http {

	class response: public message {
		bool event_stream_ = false;

	public:
		long status;

		explicit response(client&);

		bool is_event_stream() const {
			return event_stream_;
		}
	};

} // leaf

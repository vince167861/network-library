#pragma once

#include "http2/message.h"

#include <future>

namespace leaf::network::http2 {

	class stream_handler;

	class response final: public message {
	public:
		long status;

		response() = default;

		std::list<std::reference_wrapper<stream_handler>> pushed;

		void print(std::ostream&) const;
	};
}

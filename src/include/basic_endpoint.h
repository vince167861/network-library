#pragma once

#include "basic_stream.h"

namespace leaf::network {

	class endpoint: public stream {
	public:
		virtual bool connected() const = 0;

		virtual void finish() = 0;

		virtual void close() = 0;
	};
}

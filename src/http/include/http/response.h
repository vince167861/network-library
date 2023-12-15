#pragma once

#include "message.h"
#include "shared/client.h"

namespace leaf::network::http {

	class response: public message {
	public:
		long status;
	};

} // leaf

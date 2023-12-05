#pragma once

#include "shared/client.h"
#include "request.h"

namespace leaf::network::http {

	class client {
		network::client& client_;

		void handle_(const request& request);

	public:
		explicit client(network::client&);

		void send(const request&);
	};
}

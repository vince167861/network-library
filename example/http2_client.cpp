#include "tcp/client.h"
#include "http2/client.h"
#include "http2/stream_control.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	http2::client http2_client{tcp_client};

	http::request request_1{"GET", {"http://nghttp2.org/"}},
			request_2{"GET", {"http://nghttp2.org/documentation/"}};
	auto future_1 = http2_client.fetch(request_1), future_2 = http2_client.fetch(request_2);

	http2_client.process();

	try {
		const auto response_1 = future_1.get();
		std::cout << std::format("{}\n", response_1);
	} catch (const std::exception& error) {
		std::cout << std::format("Failed to retrieve first response: {}\n", error.what());
	}

	try {
		const auto response_2 = future_2.get();
		std::cout << std::format("{}\n", response_2);
	} catch (const std::exception& error) {
		std::cout << std::format("Failed to retrieve second response: {}\n", error.what());
	}

	return 0;
}

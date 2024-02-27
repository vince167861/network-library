#include "tcp/client.h"
#include "http2/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	http2::client http2_client(tcp_client);

	const http::request
			req_1{"GET", {"http://nghttp2.org/"}},
			req_2{"GET", {"http://nghttp2.org/documentation/"}};

	auto future_1 = http2_client.fetch(req_1), future_2 = http2_client.fetch(req_2);

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

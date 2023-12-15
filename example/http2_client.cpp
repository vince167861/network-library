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
	auto future_1 = http2_client.send(request_1), future_2 = http2_client.send(request_2);

	http2_client.process();

	const auto response_1 = future_1.get(), response_2 = future_2.get();

	response_1.print(std::cout);
	for (auto& sub_future: response_1.pushed)
		sub_future.get().get_future().get().print(std::cout);

	response_2.print(std::cout);
	for (auto& sub_future: response_2.pushed)
		sub_future.get().get_future().get().print(std::cout);

	return 0;
}

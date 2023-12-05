#include "tcp/client.h"
#include "http2/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	http2::client http2_client(tcp_client);

	http2::request request("GET", {"http://nghttp2.org/"});
	auto future = http2_client.send(request);
	http2_client.process();
	auto response = future.get();
	std::cout << response.body << '\n';
	for (auto& sub_future: response.pushed)
		std::cout << sub_future.get().body << '\n';
	return 0;
}

#include "tcp/client.h"
#include "http/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client client;

	http::client http_client{client};

	http::request
			request_1("GET", {"http://example.com"}, {{"accept", "text/html"}}),
			request_2{"GET", {"http://example.com/1"}};

	auto future_1 = http_client.fetch(request_1), future_2 = http_client.fetch(request_2);
	http_client.process();
	std::cout << future_1.get().body << '\n' << future_2.get().body;

	return 0;
}

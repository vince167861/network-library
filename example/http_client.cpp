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
	std::cout << std::format("response of request 1:\n{}\nresponse of request 2:\n{}", future_1.get(), future_2.get());

	return 0;
}

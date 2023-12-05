#include "tcp/client.h"
#include "http/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client client;
	http::client http_client(client);
	http::request request("GET", {"http://example.com"}, {{"accept", "text/html"}});
	request.handler([](auto&, auto& res) {
		std::cout << std::get<0>(res).body;
	});
	http_client.send(request);
	return 0;
}

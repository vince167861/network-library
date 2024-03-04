#include "tcp/client.h"
#include "http1_1/client.h"
#include <iostream>

using namespace leaf::network;

int main(int argc, const char* const* const argv) {
	const auto request_target = uri::from(argc > 1 ? argv[1] : "http://example.com");
	tcp::client tcp_client;
	http::client http_client(tcp_client);

	http::request request("GET", request_target, {{"accept", "text/html"}});
	http::response_parser response;
	http_client.fetch(request, response);

	for (auto& [req, res]: response.parsed) {
		std::cout << std::format("{}\n{}\n", req, res);
	}
	return 0;
}

#include "tcp/client.h"
#include "tls/client.h"
#include "http/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	tls::client tls_client{tcp_client};
	tls_client.add_cipher("AES_128_GCM_SHA256");
	tls_client.add_group("x25519:ffdhe2048");

	http::client https_client(tls_client);

	http::request request("GET", {"https://www.google.com"});
	request.handler([](auto& req, auto& res) {
		if (std::holds_alternative<http::response>(res))
			std::cout << std::get<http::response>(res).body;
	});

	https_client.send(request);
}

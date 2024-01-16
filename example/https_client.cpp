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

	auto response = https_client.fetch({"GET", {"https://www.google.com"}});

	https_client.process();

	std::cout << std::format("{}\n", response.get());
}

#include <iostream>

#include "tcp/client.h"
#include "tls/client.h"
#include "http2/client.h"

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	tls::client tls_client(tcp_client);
	tls_client.add_cipher("AES_128_GCM_SHA256");
	tls_client.add_group("x25519:ffdhe2048");
	tls_client.add_alpn("h2");

	http2::client http2_client(tls_client);

	http2::request request("GET", {"https://www.google.com"});
	auto future = http2_client.send(request);
	http2_client.process();
	auto response = future.get();
	std::cout << response.body << '\n';
	for (auto& sub_future: response.pushed)
		std::cout << sub_future.get().body << '\n';
	return 0;
}

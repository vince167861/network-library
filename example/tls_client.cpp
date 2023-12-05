#include "tcp/client.h"
#include "tls/client.h"

#include <iostream>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;
	tls::client tls_client{tcp_client};
	tls_client.add_cipher("AES_128_GCM_SHA256");
	tls_client.add_group("x25519:ffdhe2048");
	if (tls_client.connect("google.com", 443)) {
		tls_client.write("GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: PostmanRuntime/7.34.0\r\nAccept: */*\r\n\r\n");
		tls_client.finish();
		std::cout << tls_client.read_all();
	}
}

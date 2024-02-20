#include "tcp/client.h"
#include "tls/client.h"
#include "http/client.h"

#include <iostream>

using namespace leaf::network;
using leaf::named_group_t, leaf::cipher_suite_t;

int main(int argc, char** argv) {
	tcp::client tcp_client;

	tls::client tls_client{tcp_client};
	tls_client.add_cipher_suite({cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group(named_group_t::x25519, true);
	tls_client.add_group(named_group_t::ffdhe2048, false);

	http::client https_client(tls_client);
	const url request_url(argc > 1 ? argv[1] : "https://www.google.com/");

	auto response = https_client.fetch({"GET", request_url});

	https_client.process();

	std::cout << std::format("{}\n", response.get());
}

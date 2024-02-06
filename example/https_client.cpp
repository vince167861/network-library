#include "tcp/client.h"
#include "tls/client.h"
#include "http/client.h"

#include <iostream>

using namespace leaf::network;
using leaf::named_group_t, leaf::cipher_suite_t;

int main() {
	tcp::client tcp_client;

	tls::client tls_client{tcp_client};
	tls_client.add_cipher_suite({cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group({named_group_t::x25519, named_group_t::ffdhe2048});

	http::client https_client(tls_client);

	auto response = https_client.fetch({"GET", {"https://www.google.com/"}});

	https_client.process();

	std::cout << std::format("{}\n", response.get());
}

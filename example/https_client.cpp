#include "tcp/client.h"
#include "tls/client.h"
#include "http1_1/client.h"

#include <iostream>

using namespace network;

int main(const int argc, const char* const* const argv) {
	tcp::client tcp_client;

	tls::client tls_client(tcp_client);
	tls_client.add_cipher_suite({tls::cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group(tls::named_group_t::x25519, true);
	tls_client.add_group(tls::named_group_t::ffdhe2048, false);

	http::client https_client(tls_client, true);
	const auto request_url = uri::from(argc > 1 ? argv[1] : "https://www.google.com/");

	auto response = https_client.fetch({"GET", request_url});

	std::cout << std::format("{}\n", response);
}

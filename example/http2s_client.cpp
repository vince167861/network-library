#include "tcp/client.h"
#include "tls/client.h"
#include "http2/client.h"
#include <iostream>

using namespace leaf;
using namespace leaf::network;

int main(const int argc, char** argv) {
	tcp::client tcp_client;

	tls::client tls_client(tcp_client);
	tls_client.add_cipher_suite({cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group(named_group_t::x25519, true);
	tls_client.add_group(named_group_t::ffdhe2048, false);
	tls_client.alpn_protocols.push_back("h2");

	http2::client http2_client(tls_client);

	const url request_url(argc > 1 ? argv[1] : "https://nghttp2.org/");
	const http::request request("GET", request_url);
	auto future = http2_client.fetch(request);

	http2_client.process();

	std::cout << std::format("{}", future.get());
	return 0;
}

#include <iostream>

#include "tcp/client.h"
#include "tls/client.h"
#include "http2/client.h"
#include "http2/stream.h"

using namespace leaf::network;

int main() {
	constexpr std::string_view target_url{"https://nghttp2.org/"};
	tcp::client tcp_client;

	tls::client tls_client(tcp_client);
	tls_client.add_cipher("AES_128_GCM_SHA256");
	tls_client.add_group("x25519:ffdhe2048");
	tls_client.add_alpn("h2");

	http2::client http2_client(tls_client);

	http::request request{"GET", {target_url}};
	auto future = http2_client.fetch(request);

	http2_client.process();

	const auto response = future.get();
	std::cout << std::format("{}\n", response);
	return 0;
}

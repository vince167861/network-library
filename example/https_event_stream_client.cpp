#include "tcp/client.h"
#include "tls/client.h"
#include "http1_1/client.h"
#include <iostream>
#include <format>

using leaf::cipher_suite_t, leaf::named_group_t;
using namespace leaf::network;

int main(const int argc, const char * const * const argv) {
	if (argc <= 1)
		throw std::invalid_argument(std::format("usage: {} <request url>\n", argc == 1 ? argv[0] : "client"));
	const uri request_target(argv[1]);

	tcp::client tcp_client;

	tls::client tls_client(tcp_client);
	tls_client.add_cipher_suite({cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group(named_group_t::x25519, true);
	tls_client.add_group(named_group_t::ffdhe2048, false);

	http::client http_client(tls_client);

	http::request request{"GET", request_target, {{"accept", "text/event-stream"}}};

	auto source = http_client.stream(request);

	while (true) {
		auto opt_event = source.await_next_event();
		if (!opt_event) break;
		auto& [type, data, id] = opt_event.value();
		std::cout << std::format("Event {}: {}\n", type, data);
	}
}

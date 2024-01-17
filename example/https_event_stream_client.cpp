#include "tcp/client.h"
#include "tls/client.h"
#include "http/client.h"

#include <iostream>
#include <format>

using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	tls::client tls_client{tcp_client};
	tls_client.add_cipher("AES_128_GCM_SHA256");
	tls_client.add_group("x25519:ffdhe2048");

	http::client http_client(tls_client);

	http::request request{"GET", {"https://leaf-platform-default-rtdb.asia-southeast1.firebasedatabase.app/devices/foobar-123/state.json"}};

	auto source = http_client.stream(request);

	while (true) {
		auto opt_event = source.await_next_event();
		if (!opt_event) break;
		auto& [type, data, id] = opt_event.value();
		std::cout << std::format("Event {}: {}\n", type, data);
	}
}

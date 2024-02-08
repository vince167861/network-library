#include "tcp/client.h"
#include "tls/client.h"
#include "http2/client.h"

#include <iostream>
#include <format>

using leaf::cipher_suite_t, leaf::named_group_t;
using namespace leaf::network;

int main() {
	tcp::client tcp_client;

	tls::client tls_client{tcp_client};
	tls_client.add_cipher_suite({cipher_suite_t::AES_128_GCM_SHA256});
	tls_client.add_group({named_group_t::x25519, named_group_t::ffdhe2048});

	http2::client http2_client(tls_client);

	http::request request{"GET", {"https://leaf-platform-default-rtdb.asia-southeast1.firebasedatabase.app/devices/foobar-123/state.json"}};

	auto source = http2_client.stream(request);

	while (true) {
		auto opt_event = source.await_next_event();
		if (!opt_event) break;
		auto& [type, data, id] = opt_event.value();
		std::cout << std::format("Event {}: {}\n", type, data);
	}
}

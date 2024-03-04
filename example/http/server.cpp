#include "tcp/server.h"
#include "http1_1/server.h"
#include <iostream>

using namespace leaf::network;

int main() {
	tcp::server tcp_server;

	http::server http_server(tcp_server, false);

	http_server.listen(8083, 1);
	auto server_client = http_server.accept();
	auto request = server_client->fetch();

	server_client->send({{}, 200, "<html><body>123</body></html>"});
}

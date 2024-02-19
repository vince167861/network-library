#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "tcp/client.h"
#include "tcp/server.h"

using namespace leaf;
using namespace leaf::network;

TEST(TCP_CLIENT_SERVER, NORMAL) {
	tcp::server* server;

	ASSERT_NO_THROW(server = new tcp::server);
	ASSERT_NO_THROW(server->listen(8083, 1));

	tcp::client* client;
	ASSERT_NO_THROW(client = new tcp::client);
	ASSERT_TRUE(client->connect("localhost", 8083));

	std::unique_ptr<endpoint> client_socket;
	ASSERT_NO_THROW(client_socket = server->accept());

	constexpr std::uint8_t test_data_1[] = "123456767889feikojnfeoafoaei";
	ASSERT_NO_THROW(client->write(test_data_1));
	ASSERT_NO_THROW(client->finish());
	EXPECT_EQ(test_data_1, client_socket->read(sizeof test_data_1 - 1));

	constexpr std::uint8_t test_data_2[] = "908765432sgjnkdnkjglsd";
	ASSERT_NO_THROW(client_socket->write(test_data_2));
	ASSERT_NO_THROW(client_socket->finish());
	EXPECT_EQ(test_data_2, client->read(sizeof test_data_2 - 1));

	EXPECT_EQ(client->read(1).size(), 0);
	EXPECT_EQ(client_socket->read(1).size(), 0);

	EXPECT_FALSE(client->connected());
	EXPECT_FALSE(client_socket->connected());

	delete server;
	delete client;
}

TEST(TCP_CLIENT_SERVER, SERVER_ABORTED) {
	tcp::server server;
	server.listen(8083, 1);

	tcp::client client;
	ASSERT_TRUE(client.connect("localhost", 8083));

	std::unique_ptr<endpoint> client_socket;
	ASSERT_NO_THROW(client_socket = server.accept());
	client_socket->close();
	EXPECT_EQ(client_socket->connected(), 0);

	EXPECT_NO_THROW(client.read(20));
	EXPECT_FALSE(client.connected());
}

TEST(TCP_CLIENT_SERVER, CLIENT_ABORTED) {
	tcp::server server;
	server.listen(8083, 1);

	tcp::client client;
	ASSERT_TRUE(client.connect("localhost", 8083));

	std::unique_ptr<endpoint> server_socket;
	ASSERT_NO_THROW(server_socket = server.accept());
	client.close();
	EXPECT_FALSE(client.connected());

	EXPECT_NO_THROW(server_socket->read(20));
	EXPECT_FALSE(server_socket->connected());
}

TEST(TCP_CLIENT_SERVER, SERVER_REJECTED) {
	tcp::server server;
	server.listen(8083, 1);

	tcp::client client_1;
	ASSERT_TRUE(client_1.connect("localhost", 8083));

	tcp::client client_2;
	ASSERT_FALSE(client_2.connect("localhost", 8083));
}

int main() {
	::testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

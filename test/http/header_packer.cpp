#include <gtest/gtest.h>
#include "http2/header_packer.h"

using namespace leaf::network;

TEST(header_packer, encode) {
	http2::header_packer packer;
	http::http_fields headers;
	headers.set("custom-key", "custom-header");
	ASSERT_EQ(packer.encode(headers), "\x40\x{0a}custom-key\x{0d}custom-header");
	headers.set(":method", "GET");
	ASSERT_EQ(packer.encode(headers), "\x82\xbe");
	headers.set(":scheme", "http");
	headers.set(":path", "/");
	headers.set(":authority", "www.example.com");
	ASSERT_EQ(packer.encode(headers), "\x41\x{0f}www.example.com\x82\x84\x86\xbf");
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

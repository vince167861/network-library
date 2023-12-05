#include <gtest/gtest.h>

#include "http2/header_packer.h"

using namespace leaf::network::http2;

TEST(HTTP2, header_packer) {
	header_packer packer;
	ASSERT_EQ(packer.encode({{"custom-key", "custom-header"}}), "\x40\x{0a}custom-key\x{0d}custom-header");
	ASSERT_EQ(packer.encode({{":method", "GET"}}), "\x82");
	ASSERT_EQ(
		packer.encode({{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}),
		"\x82\x86\x{84}A\x{0f}www.example.com"
	);
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

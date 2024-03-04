#include <gtest/gtest.h>
#include "http2/header_packer.h"

using namespace network;

TEST(header_packer, encode) {
	constexpr std::uint8_t
			packed_1[] = "\x40\x{0a}custom-key\x{0d}custom-header",
			packed_2[] = "\x82\xbe",
			packed_3[] = "\x41\x{0f}www.example.com\x82\x84\x86\xbf";
	http2::header_packer packer;
	http::fields headers;

	headers.set("custom-key", "custom-header");
	ASSERT_EQ(packer.encode(headers), byte_string_view(packed_1));

	headers.set(":method", "GET");
	ASSERT_EQ(packer.encode(headers), byte_string_view(packed_2));

	headers.set(":scheme", "http");
	headers.set(":path", "/");
	headers.set(":authority", "www.example.com");
	ASSERT_EQ(packer.encode(headers), byte_string_view(packed_3));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

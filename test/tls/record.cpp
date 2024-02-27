#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "tls-record/record.h"
#include "tls-record/handshake.h"

using namespace leaf;
using namespace leaf::network::tls;
using namespace testing;

std::unique_ptr<cipher_suite> suite;
traffic_secret_manager manager(endpoint_type_t::client, suite);

TEST(record, alert) {
	const std::initializer_list<std::uint8_t> __fragment{21, 3, 3, 0, 2, 1, 0};
	string_stream __stream(__fragment);
	const auto __record = record::extract(__stream, manager);
	EXPECT_THAT(__record, Field(&record::type, content_type_t::alert));
	EXPECT_THAT(__record, Field(&record::version, protocol_version_t::TLS1_2));
	EXPECT_THAT(__record, Field(&record::messages, byte_string{1, 0}));
	EXPECT_EQ(static_cast<byte_string>(__record), byte_string(__fragment));
}

TEST(handshake, server_hello) {
	const std::initializer_list<std::uint8_t> __fragment{
		0x2,
		0, 0, 0x28,
		3, 3,
		0x4c, 0xf6, 0x40, 0x1a, 0xea, 0xe2, 0xb7, 0xbc, 0xde, 0xdc, 0xdb, 0xa0, 0xbf, 0xb0, 0x2e, 0x7c, 0x47, 0xdc, 0xea, 0x56, 0x5c, 0x08, 0x63, 0x63, 0x72, 0x17, 0x6d, 0x8d, 0x36, 0xdf, 0x1f, 0x92,
		0,
		0x13, 1,
		0,
		0, 0
	};
	const byte_string __fragment_str(__fragment);
	byte_string_view __v(__fragment_str);
	const auto __handshake = parse_handshake(__v, false, false);
	ASSERT_TRUE(__handshake);
	ASSERT_TRUE(std::holds_alternative<server_hello>(__handshake.value()));
	const auto& __msg = std::get<server_hello>(__handshake.value());
	EXPECT_THAT(__msg, Field(&server_hello::version, protocol_version_t::TLS1_2));
	EXPECT_THAT(__msg, Field(&server_hello::random, ElementsAre(0x4c, 0xf6, 0x40, 0x1a, 0xea, 0xe2, 0xb7, 0xbc, 0xde, 0xdc, 0xdb, 0xa0, 0xbf, 0xb0, 0x2e, 0x7c, 0x47, 0xdc, 0xea, 0x56, 0x5c, 0x08, 0x63, 0x63, 0x72, 0x17, 0x6d, 0x8d, 0x36, 0xdf, 0x1f, 0x92)));
	EXPECT_THAT(__msg, Field(&server_hello::session_id_echo, IsEmpty()));
	EXPECT_THAT(__msg, Field(&server_hello::cipher_suite, cipher_suite_t::AES_128_GCM_SHA256));
	EXPECT_THAT(__msg, Field(&server_hello::compression_method, 0));
	EXPECT_THAT(__msg, Field(&server_hello::extensions, IsEmpty()));
	EXPECT_THAT(static_cast<byte_string>(__msg), ElementsAreArray(__fragment));
}

TEST(handshake, server_hello_2) {
	constexpr std::uint8_t fragment[] {
		2,
		0, 0, 0x28,
		3, 3,
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
		0,
		0x13, 1,
		0,
		0, 0
	};
	const byte_string __fragment_str(fragment, 44);
	byte_string_view __v(__fragment_str);
	const auto __handshake = parse_handshake(__v, false, false);
	ASSERT_TRUE(__handshake);
	ASSERT_TRUE(std::holds_alternative<server_hello>(__handshake.value()));
	const auto& __msg = std::get<server_hello>(__handshake.value());
	EXPECT_THAT(__msg, Field(&server_hello::version, protocol_version_t::TLS1_2));
	EXPECT_THAT(__msg, Field(&server_hello::is_hello_retry_request, IsTrue()));
	EXPECT_THAT(__msg, Field(&server_hello::session_id_echo, IsEmpty()));
	EXPECT_THAT(__msg, Field(&server_hello::cipher_suite, cipher_suite_t::AES_128_GCM_SHA256));
	EXPECT_THAT(__msg, Field(&server_hello::compression_method, 0));
	EXPECT_THAT(__msg, Field(&server_hello::extensions, IsEmpty()));
	EXPECT_THAT(static_cast<byte_string>(__msg), ElementsAreArray(fragment));
}

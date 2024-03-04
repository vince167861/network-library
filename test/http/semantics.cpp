#include <gtest/gtest.h>
#include "http1_1/server.h"

struct testing_stream final: virtual string_stream, virtual network::stream_endpoint {

	[[nodiscard]] bool connected() const override {
		return true;
	}

	void finish() override {
	}

	void close() override {
	}
};

struct fields_semantics: testing::Test {

	static string_stream stream;

	void SetUp() override {
		stream.clear();
	}
};

struct server_semantics: testing::Test {

	static network::http::serverside_endpoint server;

	auto& stream() const {
		return dynamic_cast<string_stream&>(server.base());
	}

	void SetUp() override {
		stream().clear();
	}
};

string_stream fields_semantics::stream;

network::http::serverside_endpoint server_semantics::server{std::make_unique<testing_stream>()};

TEST_F(fields_semantics, obsolete_line_folding) {
	stream.write(reinterpret_cast<const std::uint8_t*>(
		"a: b\r\n"
		" c: d\r\n"
		"\r\n"
	));
	EXPECT_EQ(
		network::http::fields::from_http_headers(stream).error(),
		network::http::field_parse_error::obsolete_line_folding);
}

TEST_F(fields_semantics, invalid_line_folding) {
	stream.write(reinterpret_cast<const std::uint8_t*>(
		"a: b\r\n"
		"c: d\n"
		"\r\n"
	));
	EXPECT_EQ(
		network::http::fields::from_http_headers(stream).error(),
		network::http::field_parse_error::invalid_line_folding);
}

TEST_F(fields_semantics, missing_colon) {
	stream.write(reinterpret_cast<const std::uint8_t*>(
		"a: b\r\n"
		"c d\r\n"
		"\r\n"
	));
	EXPECT_EQ(
		network::http::fields::from_http_headers(stream).error(),
		network::http::field_parse_error::missing_colon);
}

TEST_F(fields_semantics, invalid_whitespace_after_name) {
	stream.write(reinterpret_cast<const std::uint8_t*>(
		"a : b\r\n"
		"\r\n"
	));
	EXPECT_EQ(
		network::http::fields::from_http_headers(stream).error(),
		network::http::field_parse_error::invalid_whitespace_after_name);
}

TEST_F(server_semantics, invalid_header_fields) {
	stream().write(reinterpret_cast<const std::uint8_t*>(
		"GET / HTTP/1.1\r\n"
		"a: b\r\n"
		" c: d\r\n"
		"\r\n"
	));
	EXPECT_EQ(server.fetch().error(), network::http::request_parse_error::invalid_header_fields);
}

TEST_F(server_semantics, invalid_request_line) {
	stream().write(reinterpret_cast<const std::uint8_t*>(
		"GET /\r\n"
		"\r\n"
	));
	EXPECT_EQ(server.fetch().error(), network::http::request_parse_error::request_line_missing_space);
}

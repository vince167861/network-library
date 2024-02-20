#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "tls-extension/extension.h"
#include "tls-record/handshake.h"

using namespace leaf;
using namespace leaf::network::tls;
using namespace testing;

TEST(extension, EncryptedExtension) {
	const std::initializer_list<std::uint8_t> __fragment{8, 0, 0, 11, 0, 9, 0, 0x10, 0, 5, 0, 3, 2, 'h', '2'};
	byte_string_view __ext(__fragment);
	const auto parse_result = parse_handshake(__ext, true, false);
	ASSERT_TRUE(parse_result);
	ASSERT_TRUE(std::holds_alternative<encrypted_extension>(parse_result.value()));
	const auto& __enc_ext = std::get<encrypted_extension>(parse_result.value());
	EXPECT_THAT(__enc_ext.extensions, ElementsAre(Pair(ext_type_t::alpn, Pointee(WhenDynamicCastTo<const alpn&>(Field(&alpn::protocol_name_list, ElementsAre("h2")))))));
	EXPECT_THAT(static_cast<byte_string>(__enc_ext), ElementsAreArray(__fragment));
}

#include <gtest/gtest.h>
#include "../../src/crypto"

using namespace leaf;

TEST(gcm, multiply) {
	EXPECT_EQ(
			gcm::multiply({"0388DACE60B6A392F328C2B971B2FE78"}, {"66E94BD4EF8A2C3B884CFA59CA342B2E"}),
			big_unsigned("5E2EC746917062882C85B0685353DEB7"));
}

TEST(gcm, increase) {
	EXPECT_EQ(increase(3, 0xffffu), big_unsigned(0xfff8u));
	EXPECT_EQ(increase(4, 0xffffu), big_unsigned(0xfff0u));
	EXPECT_EQ(increase(8, 0xffffu), big_unsigned(0xff00u));
}

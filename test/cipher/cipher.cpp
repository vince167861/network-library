#include <gtest/gtest.h>
#include "cipher/ecc.h"

using namespace leaf;

TEST(ecc, x25519_functions) {
	big_unsigned x9_256b(9u, 256);
	EXPECT_EQ(
			ecc::x25519(x9_256b, x9_256b),
			big_unsigned("7930ae1103e8603c784b85b67bb897789f27b72b3e0b35a1bcd727627a8e2c42"));
	EXPECT_EQ(
			ecc::x25519(
					big_unsigned("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
					big_unsigned("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
			big_unsigned("3db3f3698d52b0123e923d40e2ac47f48dda1d7da1cc35ec3461d94012fb44d3"));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

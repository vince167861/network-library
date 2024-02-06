#include <gtest/gtest.h>
#include "cipher/aes.h"
#include "cipher/gcm.h"
#include "cipher/ecc.h"

using namespace leaf;

TEST(aes_128, test_vector_1) {
	var_unsigned key_schedule;
	auto plain = var_unsigned::from_hex("3243f6a8885a308d313198a2e0370734"), original = plain;
	aes_128.key_expansion(var_unsigned::from_hex("2b7e151628aed2a6abf7158809cf4f3c"), key_schedule);
	aes_128.cipher(plain, key_schedule);
	aes_128.inv_cipher(plain, key_schedule);
	EXPECT_EQ(plain, original);
}

TEST(aes_128, test_vector_2) {
	var_unsigned key_schedule;
	auto plain = var_unsigned::from_hex("12153524C0895E81B2C2846500000001"),
			encrypted = var_unsigned::from_hex("eb4e051cb548a6b5490f6f11a27cb7d0");
	aes_128.key_expansion(var_unsigned::from_hex("AD7A2BD03EAC835A6F620FDCB506B345"), key_schedule);
	aes_128.cipher(plain, key_schedule);
	EXPECT_EQ(plain, encrypted);
}

TEST(gcm, increase) {
	EXPECT_EQ(
			increase(4, var_unsigned::from_hex("abcf")),
			var_unsigned::from_hex("abc0"));
	EXPECT_EQ(
			increase(8, var_unsigned::from_hex("cdef")),
			var_unsigned::from_hex("cdf0"));
	EXPECT_EQ(
			increase(8, var_unsigned::from_hex("cdff")),
			var_unsigned::from_hex("cd00"));
}

TEST(ecc, x25519_functions) {
	EXPECT_EQ(
			ecc::x25519(var_unsigned::from_number(0x9).resize(256), var_unsigned::from_number(0x9).resize(256)),
			var_unsigned::from_hex("7930ae1103e8603c784b85b67bb897789f27b72b3e0b35a1bcd727627a8e2c42"));
	EXPECT_EQ(
			ecc::x25519(
					var_unsigned::from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
					var_unsigned::from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")),
			var_unsigned::from_hex("3db3f3698d52b0123e923d40e2ac47f48dda1d7da1cc35ec3461d94012fb44d3"));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

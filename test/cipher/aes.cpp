#include <gtest/gtest.h>
#include "cipher/aes.h"

using namespace leaf;

TEST(aes_128, test_vector_1) {
	big_unsigned key_schedule, text("00112233445566778899aabbccddeeff"), original = text;
	aes_128.key_expansion({"000102030405060708090a0b0c0d0e0f"}, key_schedule);
	aes_128.cipher(text, key_schedule);
	ASSERT_EQ(text, big_unsigned("69c4e0d86a7b0430d8cdb78070b4c55a"));
	aes_128.inv_cipher(text, key_schedule);
	EXPECT_EQ(text, original);
}

TEST(aes_128, test_vector_2) {
	big_unsigned key_schedule, text("3243f6a8885a308d313198a2e0370734"), original = text;
	aes_128.key_expansion(big_unsigned("2b7e151628aed2a6abf7158809cf4f3c"), key_schedule);
	aes_128.cipher(text, key_schedule);
	ASSERT_EQ(text, big_unsigned("3925841d02dc09fbdc118597196a0b32"));
	aes_128.inv_cipher(text, key_schedule);
	EXPECT_EQ(text, original);
}

TEST(aes_128, test_vector_3) {
	big_unsigned key_schedule, text("12153524C0895E81B2C2846500000001"), original = text;
	aes_128.key_expansion(big_unsigned("AD7A2BD03EAC835A6F620FDCB506B345"), key_schedule);
	aes_128.cipher(text, key_schedule);
	ASSERT_EQ(text, big_unsigned("eb4e051cb548a6b5490f6f11a27cb7d0"));
	aes_128.inv_cipher(text, key_schedule);
	EXPECT_EQ(text, original);
}

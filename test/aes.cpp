#include <gtest/gtest.h>

#include "cipher/aes.h"

using namespace leaf;

TEST(AES, AES128) {
	auto clear_1 = var_unsigned::from_hex("3243f6a8885a308d313198a2e0370734"),
			key_1 = var_unsigned::from_hex("2b7e151628aed2a6abf7158809cf4f3c"),
			data_copy_1 = clear_1;
	var_unsigned key_schedule_1;
	aes_128::key_expansion(key_1, key_schedule_1);
	aes_128::cipher(clear_1, key_schedule_1);
	aes_128::inv_cipher(clear_1, key_schedule_1);
	EXPECT_EQ(clear_1, data_copy_1);

	auto clear_2 = var_unsigned::from_hex("12153524C0895E81B2C2846500000001"),
			key_2 = var_unsigned::from_hex("AD7A2BD03EAC835A6F620FDCB506B345"),
			encrypted_2 = var_unsigned::from_hex("eb4e051cb548a6b5490f6f11a27cb7d0");
	var_unsigned key_schedule;
	aes_128::key_expansion(key_2, key_schedule);
	aes_128::cipher(clear_2, key_schedule);
	EXPECT_EQ(clear_2, encrypted_2);
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

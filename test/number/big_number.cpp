#include <gtest/gtest.h>
#include "number/big_number.h"

using namespace leaf;

TEST(big_unsigned, bit_used) {
	EXPECT_EQ(big_unsigned(123u).bit_used(), 7);
	EXPECT_EQ(big_unsigned("dddddddd").bit_used(), 32);
	EXPECT_EQ((big_unsigned(1u, 447) << 446).bit_used(), 447);
}

TEST(big_unsigned, equal) {
	EXPECT_EQ(big_unsigned("cafebabe"), big_unsigned(0xcafebabe));
	EXPECT_NE(big_unsigned("cafebabe"), big_unsigned("0cafebabe"));
}

TEST(big_unsigned, add) {
	EXPECT_EQ(big_unsigned(673485u) + big_unsigned(7483u), big_unsigned(680968u));
	EXPECT_EQ(
			big_unsigned(0x123456789abcdef0u) + big_unsigned(0xfedcba9876543210),
			big_unsigned("11111111111111100"));
}

TEST(big_unsigned, subtract) {
	EXPECT_EQ(big_unsigned(23594876u) - big_unsigned(3217654u), big_unsigned(20377222u));

	// When big_unsigned underflow after subtracted, its size SHOULD remain the same.
	EXPECT_EQ(big_unsigned(0x1u) - big_unsigned(0x2u), big_unsigned(0xffffffff));
	EXPECT_EQ(
			big_unsigned("000001") - big_unsigned("000002"),
			big_unsigned("ffffff"));
	EXPECT_EQ(
			big_unsigned(0x100000000u) - big_unsigned(0x100000001u),
			big_unsigned(0xffffffffffffffff));
}

TEST(big_unsigned, multiply) {
	EXPECT_EQ(big_unsigned(678423u) * big_unsigned(12u), big_unsigned("7c3914"));
	EXPECT_EQ(
			big_unsigned(0xffffffffffffffff) * big_unsigned(0xffffffffffffffff),
			big_unsigned("fffffffffffffffe0000000000000001"));
}

TEST(big_unsigned, left_shift_1) {
	EXPECT_EQ(big_unsigned(54u) << 0, big_unsigned(54u));
	EXPECT_EQ(big_unsigned(54u) << 64, big_unsigned(0u));
	EXPECT_EQ(big_unsigned(54u, 66) << 64, big_unsigned("20000000000000000", 66));
	EXPECT_EQ(big_unsigned(1u, 2) << 1, big_unsigned(0b10u, 2));
	EXPECT_EQ(big_unsigned(1u, 2) << 2, big_unsigned(0u, 2));
	EXPECT_EQ(big_unsigned(0xfu, 2) << 2, big_unsigned(0u, 2));
}

TEST(big_unsigned, left_shift_2) {
	EXPECT_TRUE((big_unsigned(1u, 449) << 448).test(448));
}

TEST(big_unsigned, right_shift_1) {
	EXPECT_EQ(big_unsigned(0b100000u) >> 5, big_unsigned(1u));
	EXPECT_EQ(big_unsigned(0x100000u) >> 18, big_unsigned(4u));
}

TEST(big_unsigned, xor) {
	EXPECT_EQ(big_unsigned(432u) ^ big_unsigned(4394u), big_unsigned(4250u));
	EXPECT_EQ(big_unsigned(30212u) ^ big_unsigned(), big_unsigned(30212u));
}

TEST(big_unsigned, compl) {
	EXPECT_EQ(~big_unsigned(0xb5d9e214cc62e8aa), big_unsigned(0x4a261deb339d1755u));
}

TEST(big_unsigned, modulo) {
	EXPECT_EQ(big_unsigned(678231u) % 47u, big_unsigned(21u));
}

TEST(big_signed, constructor) {
	EXPECT_EQ(big_signed(-1), big_signed(1u, true));
	EXPECT_EQ(big_signed(1), big_signed(1u, false));
	EXPECT_EQ(big_signed({"1f", 32}, false), big_signed(0x1f));
	EXPECT_EQ(big_signed({"fd", 32}, true), big_signed(-0xfd));
}

TEST(big_signed, add) {
	EXPECT_EQ(big_signed(-1) + big_signed(-2), big_signed(-3, 8));
	EXPECT_EQ(big_signed(-2) + big_signed(1), big_signed(-1, 8));
	EXPECT_EQ(big_signed(-2) + big_signed(3), big_signed(1, 8));
	EXPECT_EQ(big_signed(1) + big_signed(-2), big_signed(-1, 8));
	EXPECT_EQ(big_signed(3) + big_signed(-2), big_signed(1, 8));
	EXPECT_EQ(big_signed(20) + big_signed(22), big_signed(42, 8));
	EXPECT_EQ(big_signed(0x7fffffff) + big_signed(1), big_signed(0x80000000, false));
}

TEST(big_signed, subtract) {
	EXPECT_EQ(big_signed(3) - big_signed(1), big_signed(2, 8));
	EXPECT_EQ(big_signed(3) - big_signed(-1), big_signed(4, 8));
	EXPECT_EQ(big_signed(3) - big_signed(5), big_signed(-2, 8));
	EXPECT_EQ(big_signed(-1) - big_signed(43), big_signed(-44, 8));
	EXPECT_EQ(big_signed(-1021) - big_signed(2), big_signed(-1023, 16));
}

TEST(big_signed, multiply) {
	EXPECT_EQ(big_signed(2) * big_signed(3), big_signed({"6"}, false));
	EXPECT_EQ(big_signed(4) * big_signed(-7), big_signed({"1c"}, true));
	EXPECT_EQ(big_signed(-45) * big_signed(29), big_signed({"519"}, false));
	EXPECT_EQ(
			big_signed(-2483294) * big_signed(-983021),
			big_signed({"2385eb20d06"}, false));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

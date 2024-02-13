#include <gtest/gtest.h>
#include "number/big_number.h"

using namespace leaf;

TEST(exp_big_unsigned, bit_used) {
	EXPECT_EQ(experiment::big_unsigned(123).bit_used(), 7);
	EXPECT_EQ(experiment::big_unsigned("dddddddd").bit_used(), 32);
}

TEST(exp_big_unsigned, equal) {
	EXPECT_EQ(experiment::big_unsigned("cafebabe"), experiment::big_unsigned(0xcafebabe));
	EXPECT_NE(experiment::big_unsigned("cafebabe"), experiment::big_unsigned("0cafebabe"));
}

TEST(exp_big_unsigned, add) {
	EXPECT_EQ(experiment::big_unsigned(673485) + experiment::big_unsigned(7483), experiment::big_unsigned(680968));
	EXPECT_EQ(
			experiment::big_unsigned(0x123456789abcdef0) + experiment::big_unsigned(0xfedcba9876543210),
			experiment::big_unsigned("11111111111111100"));
}

TEST(exp_big_unsigned, subtract) {
	EXPECT_EQ(experiment::big_unsigned(23594876) - experiment::big_unsigned(3217654), experiment::big_unsigned(20377222));

	// When big_unsigned underflow after subtracted, its size SHOULD remain the same.
	EXPECT_EQ(experiment::big_unsigned(0x1) - experiment::big_unsigned(0x2), experiment::big_unsigned(0xffffffff));
	EXPECT_EQ(
			experiment::big_unsigned("000001") - experiment::big_unsigned("000002"),
			experiment::big_unsigned("ffffff"));
	EXPECT_EQ(
			experiment::big_unsigned(0x100000000) - experiment::big_unsigned(0x100000001),
			experiment::big_unsigned(0xffffffffffffffff));
}

TEST(exp_big_unsigned, multiply) {
	EXPECT_EQ(experiment::big_unsigned(678423) * experiment::big_unsigned(12), experiment::big_unsigned("7c3914"));
	EXPECT_EQ(
			experiment::big_unsigned(0xffffffffffffffff) * experiment::big_unsigned(0xffffffffffffffff),
			experiment::big_unsigned("fffffffffffffffe0000000000000001"));
}

TEST(exp_big_unsigned, left_shift) {
	EXPECT_EQ(experiment::big_unsigned(54) << 0, experiment::big_unsigned(54));
	EXPECT_EQ(experiment::big_unsigned(54) << 64, experiment::big_unsigned(0));
	EXPECT_EQ(experiment::big_unsigned(54, 66) << 64, experiment::big_unsigned("20000000000000000", 66));
	EXPECT_EQ(experiment::big_unsigned(1, 2) << 1, experiment::big_unsigned(0b10, 2));
	EXPECT_EQ(experiment::big_unsigned(1, 2) << 2, experiment::big_unsigned(0, 2));
	EXPECT_EQ(experiment::big_unsigned(0xf, 2) << 2, experiment::big_unsigned(0, 2));
}

TEST(exp_big_unsigned, xor) {
	EXPECT_EQ(experiment::big_unsigned(432) ^ experiment::big_unsigned(4394), experiment::big_unsigned(4250));
	EXPECT_EQ(experiment::big_unsigned(30212) ^ experiment::big_unsigned(), experiment::big_unsigned(30212));
}

TEST(exp_big_unsigned, compl) {
	EXPECT_EQ(~experiment::big_unsigned(0xb5d9e214cc62e8aa), experiment::big_unsigned(0x4a261deb339d1755));
}

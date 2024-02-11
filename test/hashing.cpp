#include <gtest/gtest.h>

#include "hash/sha2.h"
#include "hash/hmac.h"

using namespace leaf;

TEST(sha_256, test_vectors) {
	EXPECT_EQ(
			sha_256::hash(big_unsigned{}),
			big_unsigned::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
	EXPECT_EQ(
			sha_256::hash(big_unsigned::from_hex("616263")),
			big_unsigned::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
	EXPECT_EQ(
			sha_256::hash(
					big_unsigned::from_hex("6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071")),
			big_unsigned::from_hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));
}

TEST(hmac_sha_256, test_vectors) {
	EXPECT_EQ(
			hashing::HMAC_sha_256(big_unsigned(), big_unsigned()),
			big_unsigned::from_hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"));
	EXPECT_EQ(
			hashing::HMAC_sha_256(big_unsigned(0, 32 * 8), big_unsigned()),
			big_unsigned::from_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
	EXPECT_EQ(
			hashing::HMAC_sha_256(big_unsigned::from_hex("4869205468657265"), big_unsigned::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
			big_unsigned::from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

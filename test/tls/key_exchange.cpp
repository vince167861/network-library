#include <gtest/gtest.h>
#include "tls-key/ffdhe2048.h"
#include "tls-key/x25519.h"

using namespace leaf;
using namespace leaf::network::tls;

TEST(ffdhe2048, test_vector_1) {
	ffdhe2048_manager manager({"19709ee6c09fa02bcc297a362f283c4f2055b7047e90280ca94a47c0b"});
	ASSERT_EQ(
			big_unsigned(manager.public_key(), std::nullopt, std::endian::big),
			big_unsigned("2510ad5cdddbd8176d4f4f6291c927a077770a2f274a49cee3b32da10c1b4f2e6067d1e4bae6c04358b789bbcbb98f7bca816e991ece7ddc584f85433254f2b24c0490fe9b1315d84fc320aea02b1ed87416ca31aed95220d07ca9e74aab5325e972fb5fc6594954f42d70f227855e853112c53e6af3b63f79e8666346ee7e4f3635843ade484ff927e495093f97956f95d3b8b5f938b956f8dbefbf37c85a21bb7d94bca78855e1fd90dda9b20a6d132dcef12be4a777800e48d6d2f8820f3963031e770a59ed097c0c1cdebd7a76bdea1c1d9dc8165fbf0365e7c755484a88d4379a57846cad78217f35f113e0f744b5754172354125e4126d227de637eb32"));
	manager.exchange(manager.public_key());
	EXPECT_EQ(
			big_unsigned(manager.shared_key(), std::nullopt, std::endian::big),
			big_unsigned("3a3fc442bee08241be7639ca78f13ba861a9e8fa2b6570032b2268382a8076640ed5fa9532350a6934e1c64c6212dc148b4958e332e847e2362d264c97b46616deaff8f169077c0a27c1562fc3b25df275108ecf364d5b93ef01bf37d6b870e7e2852028dfb80e0652130e5bf08c88f48dec0acb706014e0e870a97cb29793b55dafd105575ef6b8a46c81c0874b127192269dd31a79551af76a7dce2d2a7436f7a928d62a1c25c0ef306bd7f45c7172dc3a220f32b802468a3996484bccadcfbabe0d5c0d523453409a929339f5325fd6c096c91d853085bf01b98f81e6a724bf5ce13ab090785aea0080be2ee24c403d0080bb17546accc2273e9ebe2948f0"));
}

TEST(x25519, test_vector_1) {
	x25519_manager manager({"2a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0777"});
	ASSERT_EQ(
			big_unsigned(manager.public_key(), std::nullopt, std::endian::little),
			big_unsigned("6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085")
	);
	manager.exchange(manager.public_key());
	EXPECT_EQ(
			big_unsigned(manager.shared_key(), std::nullopt, std::endian::little),
			big_unsigned("24d1278ea3429f7b4b65577571194533069c65a43c9ab6217f0ddb6c1e408163")
	);
}

TEST(x25519, test_vector_2) {
	x25519_manager manager({big_unsigned("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e").to_bytestring(std::endian::big)});
	ASSERT_EQ(
			big_unsigned(manager.public_key(), std::nullopt, std::endian::little),
			big_unsigned("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f").to_bytestring(std::endian::big));
	manager.exchange(
			big_unsigned("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c").to_bytestring(std::endian::big));
	EXPECT_EQ(
			big_unsigned(manager.shared_key(), std::nullopt, std::endian::little),
			big_unsigned("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").to_bytestring(std::endian::big));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

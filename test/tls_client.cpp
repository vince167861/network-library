#include <gtest/gtest.h>

#include "tls-key/ecc.h"
#include "tls-key/ffdhe2048.h"
#include "tls-key/x25519.h"
#include "tls-cipher/aes_gcm.h"

using namespace leaf;
using namespace leaf::network;

TEST(key_exchange, ffdhe2048) {
	tls::ffdhe2048_manager manager(fixed_unsigned("19709ee6c09fa02bcc297a362f283c4f2055b7047e90280ca94a47c0b"));
	auto public_bytes = var_unsigned::from_bytes(manager.public_key());
	constexpr fixed_unsigned real_public_bytes("2510ad5cdddbd8176d4f4f6291c927a077770a2f274a49cee3b32da10c1b4f2e6067d1e4bae6c04358b789bbcbb98f7bca816e991ece7ddc584f85433254f2b24c0490fe9b1315d84fc320aea02b1ed87416ca31aed95220d07ca9e74aab5325e972fb5fc6594954f42d70f227855e853112c53e6af3b63f79e8666346ee7e4f3635843ade484ff927e495093f97956f95d3b8b5f938b956f8dbefbf37c85a21bb7d94bca78855e1fd90dda9b20a6d132dcef12be4a777800e48d6d2f8820f3963031e770a59ed097c0c1cdebd7a76bdea1c1d9dc8165fbf0365e7c755484a88d4379a57846cad78217f35f113e0f744b5754172354125e4126d227de637eb32");
	EXPECT_EQ(public_bytes, real_public_bytes);

	manager.exchange_key(manager.public_key());
	EXPECT_EQ(
			var_unsigned::from_bytes(manager.shared_key()),
			fixed_unsigned("3a3fc442bee08241be7639ca78f13ba861a9e8fa2b6570032b2268382a8076640ed5fa9532350a6934e1c64c6212dc148b4958e332e847e2362d264c97b46616deaff8f169077c0a27c1562fc3b25df275108ecf364d5b93ef01bf37d6b870e7e2852028dfb80e0652130e5bf08c88f48dec0acb706014e0e870a97cb29793b55dafd105575ef6b8a46c81c0874b127192269dd31a79551af76a7dce2d2a7436f7a928d62a1c25c0ef306bd7f45c7172dc3a220f32b802468a3996484bccadcfbabe0d5c0d523453409a929339f5325fd6c096c91d853085bf01b98f81e6a724bf5ce13ab090785aea0080be2ee24c403d0080bb17546accc2273e9ebe2948f0")
	);
}

TEST(gcm, increase) {
	constexpr fixed_unsigned first("abcf");
	EXPECT_EQ(increase<4>(first), fixed_unsigned("abc0"));
}

TEST(key_exchange, x25519_functions) {
	EXPECT_EQ(
			ecc::x25519(fixed_unsigned<256>(0x9), fixed_unsigned<256>(0x9)),
			fixed_unsigned("7930ae1103e8603c784b85b67bb897789f27b72b3e0b35a1bcd727627a8e2c42")
	);
	fixed_unsigned scalar("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
			u_coordinate("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
	EXPECT_EQ(ecc::x25519(scalar, u_coordinate),
			var_unsigned::from_hex("3db3f3698d52b0123e923d40e2ac47f48dda1d7da1cc35ec3461d94012fb44d3"));
}

TEST(key_exchange, x25519) {
	{
		tls::x25519_manager manager(var_unsigned::from_hex("2a2cb91da5fb77b12a99c0eb872f4cdf4566b25172c1163c7da518730a6d0777"));
		ASSERT_EQ(
				var_unsigned::from_little_endian_bytes(manager.public_key()),
				var_unsigned::from_hex("6a4e9baa8ea9a4ebf41a38260d3abf0d5af73eb4dc7d8b7454a7308909f02085")
		);
		manager.exchange_key(manager.public_key());
		EXPECT_EQ(
				var_unsigned::from_little_endian_bytes(manager.shared_key()),
				var_unsigned::from_hex("24d1278ea3429f7b4b65577571194533069c65a43c9ab6217f0ddb6c1e408163")
		);
	}
	{
		tls::x25519_manager manager(
			var_unsigned::from_little_endian_hex("b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e"));
		ASSERT_EQ(
				var_unsigned::from_little_endian_bytes(manager.public_key()),
				var_unsigned::from_little_endian_hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
		);
		manager.exchange_key(
			var_unsigned::from_little_endian_hex("99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c"));
		EXPECT_EQ(
				var_unsigned::from_little_endian_bytes(manager.shared_key()),
				var_unsigned::from_little_endian_hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
		);
	}
}

TEST(cipher, aes_128_gcm_sha256) {
	tls::aes_128_gcm_sha256 cipher;

	cipher.set_key(var_unsigned::from_hex("00000000000000000000000000000000"));
	EXPECT_EQ(
			var_unsigned::from_bytes(cipher.encrypt(var_unsigned::from_hex("000000000000000000000000").to_bytes(), "", "")),
			fixed_unsigned("58e2fccefa7e3061367f1d57a4e7455a"));

	auto plain_1 = var_unsigned::from_hex("00000000000000000000000000000000");
	auto iv_1 = var_unsigned::from_hex("000000000000000000000000").to_bytes();
	cipher.set_key(var_unsigned::from_hex("00000000000000000000000000000000"));
	auto ciphered_1  = var_unsigned::from_bytes(cipher.encrypt(iv_1, "", plain_1.to_bytes()));
	ASSERT_EQ(ciphered_1, var_unsigned::from_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"));
	EXPECT_EQ(var_unsigned::from_bytes(cipher.decrypt(iv_1, "", ciphered_1.to_bytes())), plain_1);

	auto plain_2 = var_unsigned::from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
	auto auth_2 = var_unsigned::from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
	auto iv_2 = var_unsigned::from_hex("cafebabefacedbaddecaf888").to_bytes();
	cipher.set_key(var_unsigned::from_hex("feffe9928665731c6d6a8f9467308308"));
	auto ciphered_2 = var_unsigned::from_bytes(cipher.encrypt(iv_2, auth_2.to_bytes(), plain_2.to_bytes()));
	ASSERT_EQ(
			ciphered_2,
			var_unsigned::from_hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"));
	EXPECT_EQ(var_unsigned::from_bytes(cipher.decrypt(iv_2, auth_2.to_bytes(), ciphered_2.to_bytes())), plain_2);
}

TEST(tls_client, derive_secret) {
	auto early_secret = var_unsigned::from_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
	tls::aes_128_gcm_sha256 cipher;
	EXPECT_EQ(
			var_unsigned::from_bytes(cipher.HMAC_hash(var_unsigned::from_hex(
					"0000000000000000000000000000000000000000000000000000000000000000").to_bytes(), "")),
			early_secret
	);

	std::string msg;
	auto hash_msg = cipher.hash(msg);
	ASSERT_EQ(
			hash_msg,
			var_unsigned::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_bytes()
	);
	auto info = tls::aes_128_gcm_sha256::HKDF_info("derived", hash_msg, 32);
	ASSERT_EQ(
			var_unsigned::from_bytes(info),
			var_unsigned::from_hex("00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	);
	auto secret_for_tls13_derived = cipher.derive_secret(early_secret.to_bytes(), "derived", "");
	EXPECT_EQ(
			var_unsigned::from_bytes(secret_for_tls13_derived),
			var_unsigned::from_hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
	);

	auto client_hello = var_unsigned::from_hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
	auto server_hello = var_unsigned::from_hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
	msg = client_hello.to_bytes() + server_hello.to_bytes();
	hash_msg = cipher.hash(msg);
	ASSERT_EQ(var_unsigned::from_bytes(hash_msg), var_unsigned::from_hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
	info = tls::aes_128_gcm_sha256::HKDF_info("c hs traffic", hash_msg, 32);
	ASSERT_EQ(leaf::var_unsigned::from_bytes(info), leaf::var_unsigned::from_hex("002012746c7331332063206873207472616666696320860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
	EXPECT_EQ(
			var_unsigned::from_bytes(cipher.derive_secret(
					var_unsigned::from_hex(
							"1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac").to_bytes(),
					"c hs traffic", msg)),
			var_unsigned::from_hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
	);
}

TEST(cipher, HKDF_Expand) {
	tls::aes_128_gcm_sha256 cipher;
	auto prk = var_unsigned::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
	auto extract = cipher.HMAC_hash(
			var_unsigned::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").to_bytes(),
			var_unsigned::from_hex("000102030405060708090a0b0c").to_bytes());
	ASSERT_EQ(leaf::var_unsigned::from_bytes(extract), prk);
	EXPECT_EQ(
			var_unsigned::from_bytes(cipher.HKDF_expand(prk.to_bytes(), var_unsigned::from_hex("f0f1f2f3f4f5f6f7f8f9").to_bytes(), 42)),
			var_unsigned::from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

TEST(cipher, decrypt) {
	tls::aes_128_gcm_sha256 cipher;

	auto&& server_handshake_traffic_secret = var_unsigned::from_hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");

	var_unsigned nonce(cipher.iv_length * 8);

	auto&& server_write_key = var_unsigned::from_bytes(
			cipher.HKDF_expand_label(server_handshake_traffic_secret.to_bytes(), "key", "", cipher.key_length));
	ASSERT_EQ(server_write_key, var_unsigned::from_hex("3fce516009c21727d0f2e4e86ee403bc"));

	auto&& server_write_iv = var_unsigned::from_bytes(
			cipher.HKDF_expand_label(server_handshake_traffic_secret.to_bytes(), "iv", "", cipher.iv_length));
	ASSERT_EQ(server_write_iv, var_unsigned::from_hex("5d313eb2671276ee13000b30"));

	nonce ^= server_write_iv;

	auto&& inner_plain = var_unsigned::from_hex("080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f071816");
	cipher.set_key(server_write_key);
	auto&& ciphered = cipher.encrypt(nonce.to_bytes(), var_unsigned::from_hex("17030302a2").to_bytes(), inner_plain.to_bytes());
	EXPECT_EQ(
			var_unsigned::from_bytes(ciphered),
			var_unsigned::from_hex("d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b")
	);
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

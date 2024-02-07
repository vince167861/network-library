#include <gtest/gtest.h>
#include "tls-cipher/cipher_suite_aes_gcm.h"

using namespace leaf;
using namespace leaf::network;

tls::aes_128_gcm_sha256 cipher;

TEST(aes_128_gcm_sha256, enc_dec_1) {
	cipher.set_key(var_unsigned::from_hex("00000000000000000000000000000000"));
	ASSERT_EQ(
			var_unsigned::from_bytes(
					cipher.encrypt(var_unsigned::from_hex("000000000000000000000000").to_bytestring(std::endian::big), "", "")),
			var_unsigned::from_hex("58e2fccefa7e3061367f1d57a4e7455a"));
	const auto plain = var_unsigned::from_hex("00000000000000000000000000000000");
	const auto iv = var_unsigned::from_hex("000000000000000000000000").to_bytestring(std::endian::big);
	const auto ciphered = var_unsigned::from_bytes(cipher.encrypt(iv, "", plain.to_bytestring(std::endian::big)));
	ASSERT_EQ(ciphered, var_unsigned::from_hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"));
	EXPECT_EQ(var_unsigned::from_bytes(cipher.decrypt(iv, "", ciphered.to_bytestring(std::endian::big))), plain);
}

TEST(aes_128_gcm_sha256, enc_dec_2) {
	cipher.set_key(var_unsigned::from_hex("feffe9928665731c6d6a8f9467308308"));
	const auto plain = var_unsigned::from_hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
	const auto auth = var_unsigned::from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
	const auto iv = var_unsigned::from_hex("cafebabefacedbaddecaf888").to_bytestring(std::endian::big);
	const auto ciphered = var_unsigned::from_bytes(cipher.encrypt(iv, auth.to_bytestring(std::endian::big), plain.to_bytestring(std::endian::big)));
	ASSERT_EQ(
			ciphered,
			var_unsigned::from_hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"));
	EXPECT_EQ(var_unsigned::from_bytes(cipher.decrypt(iv, auth.to_bytestring(std::endian::big), ciphered.to_bytestring(std::endian::big))), plain);
}

TEST(aes_128_gcm_sha256, enc_1) {
	cipher.set_key(var_unsigned::from_hex("3fce516009c21727d0f2e4e86ee403bc"));
	var_unsigned nonce{cipher.iv_length * 8};
	nonce ^= var_unsigned::from_hex("5d313eb2671276ee13000b30");
	EXPECT_EQ(
			var_unsigned::from_bytes(
					cipher.encrypt(
							nonce.to_bytestring(std::endian::big),
							var_unsigned::from_hex("17030302a2").to_bytestring(std::endian::big),
							var_unsigned::from_hex("080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f071816").to_bytestring(std::endian::big))),
			var_unsigned::from_hex("d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13bd9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd610928d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a89441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a36ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052cf93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd502784016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e750edc53370d2b"));
}

TEST(aes_128_gcm_sha256, hash) {
	const auto hash_msg = cipher.hash("");
	ASSERT_EQ(
			hash_msg,
			var_unsigned::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_bytestring(std::endian::big));
}

const auto early_secret
		= var_unsigned::from_hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a").to_bytestring(std::endian::big);

TEST(aes_128_gcm_sha256, hmac_hash) {
	EXPECT_EQ(
			cipher.HMAC_hash(var_unsigned::from_bytes(std::string(32, '\0')).to_bytestring(std::endian::big), ""),
			early_secret);
	const auto extract = cipher.HMAC_hash(
			var_unsigned::from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").to_bytestring(std::endian::big),
			var_unsigned::from_hex("000102030405060708090a0b0c").to_bytestring(std::endian::big));
	EXPECT_EQ(
			leaf::var_unsigned::from_bytes(extract),
			var_unsigned::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
}

TEST(cipher_suite, hkdf_info) {
	EXPECT_EQ(
			var_unsigned::from_bytes(tls::cipher_suite::HKDF_info("derived", cipher.hash(""), 32)),
			var_unsigned::from_hex("00200d746c733133206465726976656420e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

TEST(aes_128_gcm_sha256, hkdf_expand) {
	EXPECT_EQ(
			var_unsigned::from_bytes(
					cipher.HKDF_expand(
							var_unsigned::from_hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").to_bytestring(std::endian::big),
							var_unsigned::from_hex("f0f1f2f3f4f5f6f7f8f9").to_bytestring(std::endian::big),
							42)),
			var_unsigned::from_hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
}

TEST(aes_128_gcm_sha256, hkdf_expand_label) {
	const auto server_handshake_traffic_secret
			= var_unsigned::from_hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38").to_bytestring(std::endian::big);
	var_unsigned nonce{cipher.iv_length * 8};
	EXPECT_EQ(
			var_unsigned::from_bytes(
					cipher.HKDF_expand_label(server_handshake_traffic_secret, "key", "", cipher.key_length)),
			var_unsigned::from_hex("3fce516009c21727d0f2e4e86ee403bc"));
	EXPECT_EQ(
			var_unsigned::from_bytes(
					cipher.HKDF_expand_label(server_handshake_traffic_secret, "iv", "", cipher.iv_length)),
			var_unsigned::from_hex("5d313eb2671276ee13000b30"));
}

TEST(aes_128_gcm_sha256, derive_secret) {
	auto secret_for_tls13_derived = cipher.derive_secret(early_secret, "derived", "");
	EXPECT_EQ(
			var_unsigned::from_bytes(secret_for_tls13_derived),
			var_unsigned::from_hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
}

TEST(aes_128_gcm_sha256, traffic_key) {
	auto info = tls::cipher_suite::HKDF_info("derived", cipher.hash(""), 32);
	const auto secret_for_tls13_derived = cipher.derive_secret(early_secret, "derived", "");
	const auto client_hello = var_unsigned::from_hex("010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
	const auto server_hello = var_unsigned::from_hex("020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");
	std::string msg = client_hello.to_bytestring(std::endian::big) + server_hello.to_bytestring(std::endian::big);
	const auto hash_msg = cipher.hash(msg);
	ASSERT_EQ(var_unsigned::from_bytes(hash_msg), var_unsigned::from_hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
	info = tls::aes_128_gcm_sha256::HKDF_info("c hs traffic", hash_msg, 32);
	ASSERT_EQ(leaf::var_unsigned::from_bytes(info), leaf::var_unsigned::from_hex("002012746c7331332063206873207472616666696320860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"));
	EXPECT_EQ(
			var_unsigned::from_bytes(cipher.derive_secret(
					var_unsigned::from_hex(
							"1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac").to_bytestring(std::endian::big),
					"c hs traffic", msg)),
			var_unsigned::from_hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"));
}

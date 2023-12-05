#include <gtest/gtest.h>

#include "number\fixed.h"

using namespace leaf;

constexpr fixed_unsigned ffdhe2048_p{"FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"};

TEST(fixed, unsigned_add) {
	EXPECT_EQ(fixed_unsigned("78") + fixed_unsigned("1"), fixed_unsigned("79"));
	EXPECT_EQ(fixed_unsigned("200000000000000") + fixed_unsigned("200000000000000"), fixed_unsigned("400000000000000"));
}

TEST(fixed, signed_add) {
	EXPECT_EQ(fixed_signed(-1) + fixed_signed(-2), fixed_signed(-3));
	EXPECT_EQ(fixed_signed(-1) + fixed_signed(2), fixed_signed(1));
}

TEST(fixed, unsigned_minus) {
	EXPECT_EQ(fixed_unsigned("78") - fixed_unsigned("1"), fixed_unsigned("77"));
	EXPECT_EQ(fixed_unsigned("200000000000000") - fixed_unsigned("120000000000000"), fixed_unsigned("e0000000000000"));
	EXPECT_EQ(
			fixed_unsigned("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
			-
			ffdhe2048_p
	,
			fixed_unsigned("700000000000000005207aba75d44b5655023a9dfd8c2c30e27463a7c31d2c96a561ec9beeb9bcc04336c6231db64c10682d01c9c9cf38a27097e4dfd513b9e852c20e12a2a029a9edbcc0ae0a0f9912f7a9c9aaac212e50c4aa8eca180a836ca67b0f38f1f1974881d5976250c10178de20ea75ec95218cacf5335b0b7c5868543f54e7d4cdb049e2ef756b44d371c04469525489f280b97e2b0bd5c21c6b20b51a912189c8d44e6f4f8583711f5928f61fd031e32081d133fcbfb32d7cbd09e6e8d0163167a7c0071b0edcd110d7e7c3c01c4e4b390528cc44a0343d13ddffa3a710e7c82e97c4d390cb5d93e4d10057794bdc79ed7a3680000000000000001")
	);
}

TEST(fixed, signed_minus) {
	EXPECT_EQ(fixed_signed(-1) - fixed_signed(-2), fixed_signed(1));
	EXPECT_EQ(fixed_signed(-1) - fixed_signed(2), fixed_signed(-3));
}

TEST(fixed, unsigned_multiply) {
	EXPECT_EQ(fixed_unsigned("78") * fixed_unsigned("2"), fixed_unsigned("f0"));
	EXPECT_EQ(fixed_unsigned("ff") * fixed_unsigned("ff"), fixed_unsigned("fe01"));
	EXPECT_EQ(fixed_unsigned("200000000000000") * fixed_unsigned("120000000000000"), fixed_unsigned("24000000000000000000000000000"));
	fixed_unsigned n("c953ef9abb3009243f23c6098a9569700a1700b718010c510");
	fixed_unsigned p("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
	EXPECT_EQ(
			n * n,
			fixed_unsigned("9e54e9c63889168a4863020c8ac813008eb9f6a437a30e7e5d41e60714dd27fe7965dc36f61620f9de4dce1e4939b1a100")
	);
	EXPECT_EQ(
			n * n % p,
			fixed_unsigned("39f6a437a30e7e5d41e60714dd2815fa008fa35a6f79809d001bfae2ec83b627")
	);
}

TEST(fixed, signed_multiply) {
	fixed_signed neg_1(-1), neg_2(-2), _2(2);
	EXPECT_EQ(fixed_signed(-0x100000001) * fixed_signed(-0x100000001), fixed_signed("10000000200000001"));
	EXPECT_EQ(neg_1 * neg_2, _2);
	EXPECT_EQ(fixed_signed<32>(neg_1 * _2), neg_2);

	fixed_signed n("cf24f849a73a7ea45c8515df741d96dc3810050f2ca6dffd3e147b04de09239f");
	fixed_signed r("a79ccedde1f66a738dd14a6434bdb0253dff84a4e4456cce677de7f07eb79c01490d2999b9cd1d5c2d92862e622ca2c50cd50a6773c036690defc1134a22dcc1");
	fixed_signed p("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
	EXPECT_EQ(n * n, r);
}

TEST(fixed, unsigned_left_shift) {
	fixed_unsigned x150(0x150), x54(0x54), x0(0);
	fixed_unsigned x15e33("15000000000000000000000000000000000");
	EXPECT_EQ(x54 << 0, x54);
	EXPECT_EQ(x54 << sizeof(unsigned long long) * 8, x0);
	EXPECT_EQ(x15e33 << 0, x15e33);
	EXPECT_EQ(x54 << 0x2, x150);
	EXPECT_EQ(fixed_unsigned<0x89>(0x54) << 0x82, x15e33);
}

TEST(fixed, unsigned_right_shift) {
	fixed_unsigned x150(0x150), x54(0x54), x0(0);
	EXPECT_EQ(x54 >> 0, x54);
	EXPECT_EQ(x54 >> sizeof(unsigned long long) * 8, x0);
	EXPECT_EQ(x54 >> 0x2, fixed_unsigned(0x15));
	EXPECT_EQ(fixed_unsigned("15000000000000000000000000000000000") >> 0x82, x54);
	EXPECT_EQ(
			fixed_unsigned("15000000000000000000000000000000000") >> 64,
			fixed_unsigned("1500000000000000000")
	);
}

TEST(fixed, unsigned_compare) {
	EXPECT_GT(fixed_unsigned("33"), fixed_unsigned("32"));
	EXPECT_GE(fixed_unsigned("33"), fixed_unsigned("32"));
	EXPECT_GE(fixed_unsigned("33"), fixed_unsigned("33"));
}

TEST(fixed, unsigned_modulo) {
	fixed_unsigned x91(0x91);
	EXPECT_EQ(fixed_unsigned(0x1243) % x91, fixed_unsigned(0x23));
	EXPECT_EQ(fixed_unsigned(0x1) % x91, fixed_unsigned(1));
	EXPECT_EQ(x91 % x91, fixed_unsigned(0));

	EXPECT_EQ(fixed_unsigned("2344b72002994a6c") % fixed_unsigned("09cc3c85ddda6f53"), fixed_unsigned("5E0018E6909FC73"));
	EXPECT_EQ(
			fixed_unsigned("bc2f2ce36012a58a7c358e43ebb8f360")
			%
			fixed_unsigned("05936dd643532fa1b05a3c644c50039d"),
			fixed_unsigned("42E0444B25981B2C093C55615687C23"));
	EXPECT_EQ(
			fixed_unsigned("a4f55d2616b9edc25ea7b049e37afd580f21e7e913ee038082fabb4e17c02f19")
			%
			fixed_unsigned("84e1146e243366336baed10b3f7b70046b011e126d98254d9f84fef8aaace7a1"),
			fixed_unsigned("201448b7f286878ef2f8df3ea3ff8d53a420c9d6a655de32e375bc556d134778"));
	// 256 bytes
	EXPECT_EQ(
			leaf::fixed_unsigned("e6b11ea73e642441c4685653ce840501297395434f0531f73bd3fc05988a88a1a96459bd487afe0e2039bbd26f6c703e4f3e9d04fc20a4e5b273a66494302d842f190d5f4e5817df185ae07b8e36e0818200ddd49852775200fa8c72711f732687987a54e6575e32315ea9b20b389ed4d5f44dfe0ba62748a6056818dde5c71ebd3534197f9dcfbeabc9acb69fe43bdc6aeacdec2def191f8858dd5510727ef8c7716641cff0f6d55a6f3d89bbe0988d912a1ccae4c7af5197fad3ab60c4f1351ac03842b52dd0548f5a667a44c6a619bea8716ce7876751f5743a915665506bb9e729bc0bfeb0b071029dc13f3494f669dae50765047544a6d4f2786ae3fd88")
			%
			leaf::fixed_unsigned("75af04e955c8375f19feb8ff9a0a39e8eb57ef17bd6ee899e4fb99c49745263f349587873e177f28d092e7925a96712698897a0a638f3801694d8bacb123a1dde6a7aff1e38a0052aa79779e3193c8531fad9ce06137e29e1eea09ccb31719a4c668a04d269abfb26ad6e8c1f4df6c7dfc9578a863bcc84ce8c8cbd0e53a99a4cd97c15adc8339790155a7a77484dab809e4740625d05eba43d9479efcc37c063b15ffdebc017bc92ea020429f4d0ed37875cf7b9f0d39846523417c484b42a1d95cbbc527dfe09d8f649d2858e7edcda70ac0cefcca9374f2fa50ab9b437cb108f1def53f878388a8892cd96dc2acb7af48d6e7a9f4d2d1602e57b446281952"),
			leaf::fixed_unsigned("710219BDE89BECE2AA699D543479CB183E1BA62B9196495D56D862410145626274CED2360A637EE54FA6D44014D5FF17B6B522FA98916CE449261AB7E30C8BA648715D6D6ACE178C6DE168DD5CA3182E625340F4371A94B3E21082A5BE085981C12FDA07BFBC9E7FC687C0F016593256D95ED555A7E95EFBBD3C9C47F8AB2D79EF9D72BEA31A9645AA74050F2B5F6124610659E6081EBA65447F95B613AF02F28C5B666313EF7B0C2BCF1D471C9389BA18B44D4F45BA75CD32D7922F1879AE9341637C7D8D4DEFB6FFF5C951EBDEB84C179DB09DEABCD3DD0279E9E5BB21D3BAB0F54AC6CC772D27C87970E7D171E83EBA920E1FBB0FA27346A69AC424BBE436")
	);
	// 2048 bytes
	EXPECT_EQ(
			leaf::fixed_unsigned("afc5edf7856600b60eff3217f3181b12aabe30fb26e5300bde2e8f4268790e5fba73bc4d54a7cbaa176de2284de51e614b66cecee0d81f97c0e1d89f53355122df68f1e379c8e5f863c0f7e76243a6d5cd942e137eed7d61b90263f4efa290a46ba049867ca99789becc1af5a184cf0c603f30230c7520363276bf5b526b0c6b1f5c46a787674666701f0dbfce5c0054a6940e8296c70c582f9e45e8a9977b77c797297fef20a7a84b1d1078535aab1e28f8c3c420a6c7777e0bc952b71800aa7a80fe9ce61057d3f88a4c68b5f886fc945cc379095b5b0aaeb4fafac50700392445eabc0d2c4aa69d180b2c5d2d792619d3c90e77b43ad8b5be13a98b89a52f61ce9cae3f63b9d1ff24c0e65464f4eb8cfe350829cc022dbe9ce9f92d8380c55e95c516e590aa63aa1811f16bb7346949fb16984a2735e04524cf814b2880aa4f3b671b645712060054bff021f4f6f2885d71bc76ea268e0951edf606c3eedd7d1ab4895d6cd16eba18aaddbefdfb620cb09fe22484f3992df3aaf53a0c2ae13ce42ae156834730c5af64607d95f29c7c90f45bb9ef4cc6222bd14c454ee71c39e84ba17e43b0b10fcbf6b2170ea86cf16e2738993bbde947cdb8fd53ca9483326e6f7a32bf5885680a15a2af33666f7875aa00125de215d4f53634baa128cba42e3183d7d4fc0a3f7c3066ab2e07323148f5a653ccf8b4f6216fabbf5802a392b1d45a3f4b22ac09071985a38c04a6cb0d9dbea4e2bc6fc7fa8bdd94926915a5c113a8c17eaf0d5f06f84664345a9ed40101c7e1d05fcdedeac283e108aab14ad155e18b4c9afb8a5bb3c5e48901659a934deb54c0f66b2d89f2ca639f76eb1398bdca77c1fc91ccddce864bc424de5bfc75ec17ece58126d35444f7affe9813348c9b103c93253ea143e52a80e9862d67104f6fc3c4ca75690d0959d59502cbde78182578d148c5b7ec36aca0675a61429fd6612eaec5b319689226c1632276e61c2508b20990bf1a9d89574e853b9b5f0a337b492e94099b177da427f3c2b7407ecbd54f8e5a156d365b514310f4720b11b5e25e991948ffd047681aa2a516193d03b1713f8ea9197fc51bb962e304754d0deec63a6ee62fa32a6de54d7fe9ffb6e107abbb32ee97484f8bc3ed1f6f6eb2652fb4343976fc1d487e72ed938cc1b57080ed258fbb0d387bdd49ec6c0c1acc45556b009107ef797a663c6298edf57dd5f3ad4caf64eb578ea69f572735f0c6300b50edf3ee66079be8591913ae8be53c6937ad16d6822702a949dc78cccb64a77a3627826a76055a953608ac65c07df6a595844dd094ae42faf7aca1816dfa3732e7e5b5917c17ee84aac1905d8d8da89f2d2b6750ad37d2baaa8cabdd2637b3f465e21145bf1d417b3675db295f1a5894c04db9cf310792e35d297b77f0dc4ef246edeab7817eb38cfceab53c7c852a9ccf488f1d809cf55208dd416dea095625e2309992c133c60c611cdb04c1e33f0085b2638315da7b1c722a02827eb787d905224d3a56af6e2266110016a542c4be1982b27332096085f307d71f013155f8436a6b20571c9e10d3f1528226434e58965b053caaa767b2d088ee19e217c9b88684f224924f20fffc53825e16af27ad4a0a9740ada99cc6072a79866687268a35aca04c0728bd7ad98f1e800b37d5f6ca2b647f046945c7be162b38f073b10d05fc71859c012a67cdfdae3d19213702e88ef9dfba2bfe32bcf29f3bb451e8fa393ce2c791bf1f4879a6e88514fcd32f6406f8440424a10d8932d90887c875280219b4fbc88b7706afa03671ca1fd298af8029db1f48546387be7ea87a150fa9ffe4862443cc3f36d6cd1e6f7becdf6bb54566f87b7a54e22acb4c3b198934070ff7b44241fbf55f6430929042fa5fcf0aa8d6634096ca2c2ab4838c27f67903afafe81b3605613a31c346ad9222806cf61c409dfa3cb2cc0e7d1d1caa8ffb0ff027a34a3fb3b19722f6231f92a639c92ed5cc7ef1a906518c92ffdd9c4d5f71d77d54445e70b5309600e54bea1348c9fed8a9afde0ca680ae8c54a356cdc374c425f2cb340a04c66f7858e91431c540d3f46c768daec5c40e2092134f5660ad13cb8d0c8bee482ac696ae09903319061076b010f27c121efd5b3aef4818a4aadf1f5f78dcb8185883c9ba322171ab97ba2e615ff3333f9d1a038ff0e3cc20b39c5aaba634092462dc8e52bd73f3134e37865b4c8e60b5da6c72ebaf37d0f1853d82522542caf70e5a6bd1eab624587d6cdc7813a8fd80638411a16db6811eeb8ae04953ab1c48460830e1410809a1320efb087c8d7d36c96acffdebfdba0215315a967e9be84343775a3597ccaf2a56e6c84b78e8072a423de8d6e32c3ba2c4fd3a7c3dd617ba4ef459757f086207801a431a2d591bd42fd947c5b19d5f8a37f3e5ee27034a75abfb3d6163da716b26994896c9a41275617be3ab6105e03377e77bfa8c782d5d5d7daf64b86684507065bee1333378288b4df1155b9e5a48038898c9d13117a9a9fc5e4d096fa7955e6d9d9ed4d4306a301ae9e7f42c696859d0202542744ce32ee870e0a9cde405086eb3b2239b202919f9f017c3fb9c6e714d5a3403f4b2393dcb6d033fce6dc29aee9ba653594d201221ff920b34b18f0fe1bb6f84a959ba6a006ba988edd3c8017296ecdfb8fa9607fb0010ca6562776c4b4c475223b173edba615e0fdd627fd4dab79f50677fbeab8885ded7a6936cdda5041a359059006a015e7a2d4d1a6028e24578d4ffbe8fcf5b294ba3961cab014987921d3f023bee2f2cac73048a65a3764a3811d81598ddab2a4c00c3b6e6ce8ce1ff7fbc04b8a9750a05fc4c1e22214693023f257a6794ab9deb8ae224bffe3808da1439d38928285cb6")
			%
			leaf::fixed_unsigned("ab3d3f6df2f29a90b97e1f27ffbae6dfda6d5f510128ada3ce4d22e5ca6734a5bd79e83c185c3d36ef9abde8d82c32cbc25078d967e59cc7aac30f0f051cd27d4a2d68b8da0e3e4d7181160908fb209dcc7b0422322e03c9d48c99ae17f2c9357eed2aad381b5d9844c7d9ee4c553f4acef15f4465256c4ba3642c8cb2ef42450ebff4c681a3083d6b14806514a5a812340955c21f2ea826522e56854140d908e350d9e846994d8d14e09fcbb7756cab4ef2fc7926f939f1fabbcc1229478c8610700612d6213bd312d65ebd4f90883680bc772d3333f0406187d8c9a2fe6cb54fcd3eb7172a26c2acf128cbe8c7ec2fc761f6046a438d7b126a20f5c9c4abd7e944dd80d7ac7aad3aba37069d00170873c0299f99f30d13322d50558cc4ae313678e8f15f1ce44c1e300c4740d86e19a455703808c63d6418647ebbbf833cf6361370989656b2b53136589af612667abef0ed415945459f74284cd38c8cdeb75f418246575cf2819376996d9fb651e0d6db956e7351aa59b1ee8e4601cf7b36504e10191d6197bbb2ce71496c9acbe612df19709e8c4a8f349916a3c354b9c96d588006b1591e57008a660a8d1b7c002fd4dcaae2f80e3cc1f2c8fc0872b6b8909799cecf1aeada8bd263906f68cc78943b660ba268b861aaf4e23e8cbd8fe911548370d2ecc95c01af3bc4262d965d5ab25f7f932a619c8c7f339a3feb6174a535b294815e03f737870a99ef53c2025819cf5e82c5ca27ba6e5109e121451d4bb8add020a3944cdb51c477647a6cc8cc24a7a415aaa1755b6e439bbb2d70dfb75a5574766ce585c1beedb073e51f36f1e2b8d0c108a4f7cc28ab6a1aead2d4a6d211ef7cc3eeedef6f066cdb4bd955c8cff5db52af43a0afcdf81da294335014ecb0f66c10deffceb741072a28a0ef7b61a6d8916c42c0fd278b3d1b6ab12a9dcddb0ff2e6df5a95f7f5173ed47055cb1ffa5c0df1010bf7f0ebe493655bc034724a035ba33b5b6be702b9a9bd57a71d9dce04e3b99a60b4ddaee103ed7421dfb139004dada1e31fc53ba67ccd9a8c192a26276112d26585f202b32f6e5a525369630742b85de569af35bdf87d32e6ba8b803791ec5c8087e20e2e1171d7110e4d2db4e5c37366da525f6cacbe9b7e106e71a7db63f41a5ab263fb1d8ede9b214c76eec149c9056ecc2852521047a7a9543e22f9b4e4d7c40c755257edfa7576fee10970f0f506c9151a8ee9d5591368ee4f6a0ea6a40feb086ea878f85c5eaf04f3d1a937017b8a4f6b6d1283d54e88e6022613284b9f59cfa94012246d771664bd17a10ca4a4c5a01eb8dbc53f4a65b920e38d15489c7723557eb0f7bab56cc8270985bd65698f1e5d612d4583622e6da2b63302b6e52628e52e3e88e83f37493a428e74a3596e07f648df1d01dd70f964f64a1b0e9776117182cff0bff03e4161ac8a79d3c5d1af44d3a6a84226981d01cb00ddb5b47bab275acedd76d280654e78f80f4199166b97ef8890a495c1f6a788024650739658c8ab1b2b7579f403c4b1376b1c5f3f202c0feac1eed001b9ffbd036b268a77b8ddfc3ca0c99ad2a81903b7a6595c7e0c7ed6d9bbdc3f7dc630fa04e5abd3d5f4e1583657098ac24cdb76b604551b378beb96f1c54228fad646d17ccd47ebd801a96eb651cb19161cdd0358547e9ce70d175e601d11084325d7c286177bc821cd1968ecae246dad7233516d2b145df4969e2b54931d4e20198efa89c7e74ee3e1dd23f8db4fa62aebd727c7bb5f969ae93b2729f079dc742b90605c05bb4e08edac3f5c7742cbe1c18d12f5c089cbc60161cd380195d9ab58e2154998828bac1faa6b9bc6e5f3d9e9a7197432924b4dbe3ba7e5a09e279f5badcd5f75b205c125d89a79f87e597ad98087c5506334c74424b591aa32b1d070ace166eaf688f5b6a0e50c6fd65a83604c27627ca3fc0fca07704cbe2eead66c1e655f48e5c6f5be699145c677d46b3bf5b40de1da4da72bd10455aa0412aab5bcf40f81cdfd7d211579b7a5b5cd89211ad6df106dce98da823ace330e7976eafc29283d5a171588d9e9c07c91300f2121ec0df6e6baa78922c1e3e06a0e514f68fe5ff0047b1b235d2dd057156796bae9fbfeaffbbc5af1cede36232d435c78d900e46ba1bb8041b2a8279b2713d4accdb333603dd9d1a0121c251ca6ac862398fdda4c156835438aa50c9cf079518a1571bedc40fae0658f9d1e5b85d9d4297a491b7cc071387693c29c2caaa4029f48163320d11bd1b2c3c8aade3ab3b03b870971a754049f188bda1f01200c47552a5e3db4bf3fbf0fcc8310d6db25fac6740f0f176d6fdaab5cc4276f38078fe8ab7f9ea4cd999266b239a237e1b10123f6176e3af062020267582969298a7f0c1dffc10ac46514f193597a30849ef9a634256a4b8e1e15f64bb481265c9544d15bcdc9d578decb393aea20614ef05c3b3e852aae006a9b6947c026d2dc1eac5ff589ee533561a6b9e57fd61618116edfa90b4b07bfca9150fc242df154bf8785ad9ca6b0517db0e8d7e080990bab969d2f139cdb35ed6ecd48d473b1105673361412cd377b517f1012cb79a5455dae7a39d428a6e747d30b39c879f5188842012e82d921e2f78db41d1e00286794d7aa92fb89332731f149e0da6ea63e471b8d5498788e14bf964342cbdbc1cae7e4c07567798a2efda76b1d2eda1e0b362a908000a8a1149b27c7b106cd75c438fdaceffa555f9c61ffb7a6675f74ff63a256cca056201f35012ae263e2fe0a152a16037741961e784d989f9af901da2d8118b41c029d4f7531ddbc271da541dbc2f40610acf8082742337149b024b5c93fd817e52a63430fc7848e149e8f16eb19bc1e995f27e5516aaf681c6762dcd2"),
			leaf::fixed_unsigned("488AE8992736625558112EFF35D3432D050D1AA25BC82680FE16C5C9E11D9B9FCF9D4113C4B8E7327D3243F75B8EB95891655F578F282D0161EC9904E187EA5953B892A9FBAA7AAF23FE1DE59488638011929F14CBF7997E475CA46D7AFC76EECB31ED9448E39F17A044107552F8FC1914DD0DEA74FB3EA8F1292CE9F7BCA26109C51E105C43E29050A8D5AB9B65842728AB8C077986431DD6FEF636856A26EE4464F97A8875A1B363C70AC9BE53E72DA05C74AF9AD8D85834FFD408DD074246A10F88A0FEF1C00E5B3EDAB6667FEC613A04C4BD6276ACA4D2D223122089383D478AC04F60223E3F026E26074658CF65271D30A0D70AD5DA353F2B3C1C4F9577889BF2D67B73F24C46A89DFB764DDE3193E0B688FD8F51A8C6F99A3A0BED294281CDC258673C6178BE805AA2ADEC64FA5A5A6604160F87C2CC050C58BA543B41927F682CE005F50CF1E67552BE29077C96C847B1DA4E0EE9529A1227A3710261DD93243060FDEED26A211701F47A98135D50A73B133493F7C051CAF383CAFAAEC961AC83921AF7512E0F31710FB26B669B1DAEB1B630236ED92BAA881FA2D52CC8FCB9ACCEA925A0F4190A789F32C6CC1994A8DB643AFAC85DAF0014B57DDCAA1D6D5AB63A46DAADC37B2123FCA99F6E43A43F46FF529B42A0053F62DE398E292D9AE1304E832AE3DCCF4A2850070D4D6969626C0A2971869A23C117F6CA12EED7C21C5BDED1EB4D1800EEBB43842A472F3CE60221CF2480D8C3AD3B37123F85A0865D8A0DB1AC083B533CEFFB9EDD607DC5A23CC25BE58927C7EE825DB39D19377006D14DFB575C89CC61570A3E22EA8B0951A93B851736161476048B4A4166CC6ABDAFAFE0DA3DD6EC81970784B88932C8010C53DA1E077055C27551BCB47FE47DBA4A42BB4256FEA02DE00584896B2056976DE578209784181CC3E6AE3D82E109D083291F1EE2FBFF71F6DCBF7049622A57A533DADB9BB287CAD935C07624273D221AD0ECE3553339ACFAD912D947DC13C2E978F943354BD689CA03A7FA0D78F45CB87A1EC76F5A7FAB4D475766858E0EB8E814BC6B3C30DCD9438AC4852C2AFD9FC6EB8E1A93F6A4A07233C2FFC49E9CCD65CD9DDEE5E4D94FC5C73766EDBB2892C21E847CC1444E8E2DF0551A15F0040BD5450401F1C49B94D60E40EF86B753E81BFA35C8A4C4110298B39A4C462C68E225BB61BB943E304280E4E682376F69CCC82BC57A89BD63CFFBCC9FE13CD0276C5FCAA49E4035D98F36F60BCB4FF86F16AC000AB9B4C32BB9596C6072A43E56281670DDBE310A65C1A83119B354F5BC0DF0488DFA90AF48F8A1F326D571BB4D953A5D29D191A58C26FD3B306DAF0C5669F196FC5FDC18EDA718D650949AEB894FDC1632B2C1F9638133CAD8D9BF215E016064BAA606129114A0440279E06F77758A82BDF5341700D30BD0C2AC4FE3B237E125574C94BD15821AB609B1AD5CD078B25047AE517160C6B3D83A608845C94C6087670CA6CAA428B93E1856CC0880FFFD6BED1D9A3FDE6C3073A9B8622A17E1386AE66533411DD509B3119071D473198F4D843E0A89E3EA1D43327B7AF7E2A4AA0F001A8BE9E2890D914ACAE9C1BE6CFB3A0D91E4E9D6DC8C9A549F79BC9D3B0F745B57C0921BE05D441E8508B9040550D6864B474057F4EC487C40569EE5AD29E75ACC797F751E767A10522F5CA9BEE86EE80A963CEE7C17B1FD9408FA6EDE595BD7A9BEB238DD2DE29D5511B9AC2EE70715593E3AFE1FB4F9E57425A2925AB67A8A761A91AE979E398B8FC945C3814CBFC5E66F2DADF37AA385D6A900892BFA2EEF65E151DE6872B8628A4FD2132FA606761FA782421D39B0FE72A959245C5F782B31BAABD3EACFC8A2D249BBDDB66A79A45AE811C235AE56BB239156979D809BA45A19BFC72149A8081D1BBB749979CC4B95F257F647C2DC1ECEC2A31D6590A7978448E3035427F504E32463E7195B0A741DC54814A20515C7E4EB456B085BB4CFB7ED7C5D801FBE28EED32E6906B6255AF56C73D5B3B78F04B17C2C8F871EAEE6ADB17038A6BB27B7DDB2C6BD19A4C86CBDBB5AB301B05F2E728D9F30FD932DD0DB1CF048C03E02DB683C1FFED624D23C711F168911A5A6F814672D5491D07607AF3B600AD33E8DA2DF792CF3FA3C6737DA3F89B057030E8A2A65D74A3F86459F0878E53212377FD5CE36AC03322D950454370F07E7F563F9DD96BE9DDA18F5B45606C28D118BC10ED11DB0E56A869C0C1E0ECCC3734722DC12DE816DC424A4C0B5C41F639B7B8A5D6EDBD7AFA1579E38C44B492906E270710D4F9B2DF42F45A3BC8BD7DB0B3B893F4D7F13745F30619ED26A3F08B7F1C08222E07E403AAB841FAB1E68154F0A0060725E208458B56C24A1A3BD3B062258B2FEAFFFC4407BF0F7EB51867887AB5A8C326B7F72B64CDA857D0110CFEC12AD4E0CC1F09159D5CC3CFB7FE6AD78B411A94BB04CAA1AE4D397B8FF10EE59D36AAD3460C068EC68212897F8C7992A8B537D903ECBEB13CB880D8FF3FE01B857C0B098D81E9F9F8B7BD4C2123EB5889AF81DE3C5D8F3A54BCF4EA37D3A7040EBB37608A3697CFF23B373860A48B0D5DA054AABA1581629A48A672EC30E97870C3D6547AFDCD3F3FC1CCB8AEC5A5300211F997FD338A1E9386AE943D935F78DFFB5A2D626D607F2F88E4822D4975B7CA2C393528E5A4ED0FF2C11D49AAB89445139C5627E54CE27F2C39A304289FCEB7DE12C1A5D9F9A372884567B835D8B2990A8C5F168AF64DBFD2C22643D3D4DC2BEC5D1F3679801933BFB36919CFA662A0F52D527EF1EBD649A0D8FAC2DFFA5971C005E8703DCFB0D62194D9D83D88936EF950543CBC74063CF6E34FF277A0EC52F61C8700712606269F102388A98A6B6CC0C57FE4")
	);
	EXPECT_EQ(
			leaf::fixed_unsigned("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
			%
			ffdhe2048_p,
			leaf::fixed_unsigned("2903d5d3aea25ab2a811d4efec61618713a31d3e18e964b52b0f64df75cde60219b63118edb2608341680e4e4e79c51384bf26fea89dcf429610709515014d4f6de60570507cc897bd4e4d556109728625547650c0541b6533d879c78f8cba440eacbb1286080bc6f10753af64a90c6567a99ad85be2c342a1faa73ea66d824f177bab5a269b8e02234a92a44f9405cbf1585eae10e35905a8d4890c4e46a2737a7c2c1b88fac947b0fe818f19040e899fe5fd996be5e84f374680b18b3d3e0038d876e68886bf3e1e00e27259c82946622501a1e89eeffd1d38873e4174be269c865aec9f268802bbca5ee3cf6bd1b400000000000000008")
	);
	EXPECT_EQ(
			leaf::fixed_unsigned("8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
			%
			ffdhe2048_p,
			leaf::fixed_unsigned("9a95e9ccdf4202c7547bd295a0093f792aac64ef01d71c3a49d0bb1b9e31b22b0a094622968085b369a8c4480cf5a750b2f93c58d7923d51a977667744e5abeb1ef90d232944b538eb65cea16757d5fc55ec2395c6d4ec5e4ddf5124db5abd62233107b1ebdd817b3f17ea7fa9ada909b1710f5d827135c6db2b31122a87ca33cc97a9550376f5ff99bf1908259f5cd196fc0d99ca87d6088afc615c3fb2616cafcfb960027ed9f3f7778848a76dbc7d7ead668c888366058b275c79fc52b3af810ff8a39b3c78eec3bf5066d36ae09a5d5713695d64257012d9d4937f5b8557ef1f33030716e16e6631b152c2eaef58c94038b8e2c0a8280c3df1b5e9c527d0")
	);
}

TEST(fixed, signed_modulo) {
	fixed_signed x91(0x91);
	EXPECT_EQ(fixed_signed(0x1234) % x91, fixed_signed(0x14));
	EXPECT_EQ(fixed_signed(0x1) % x91, fixed_signed(0x1));
	EXPECT_EQ(x91 % x91, fixed_signed(0));
}

TEST(fixed, unsigned_exp_mod) {
	EXPECT_EQ(exp_mod(fixed_unsigned(2), fixed_unsigned(3), fixed_unsigned(7)), fixed_unsigned(1));
	EXPECT_EQ(
			exp_mod(
					fixed_unsigned(2),
					fixed_unsigned("ffffffffffffffffffffffffffffffff31A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE4741"),
					fixed_unsigned(689)
			),
			fixed_unsigned(0xd6));
	EXPECT_EQ(exp_mod(fixed_unsigned("2"), fixed_unsigned("41"), ffdhe2048_p ), fixed_unsigned("20000000000000000"));
	EXPECT_EQ(
			exp_mod(fixed_unsigned("2"), fixed_unsigned("fff"), ffdhe2048_p),
			fixed_unsigned("9a95e9ccdf4202c7547bd295a0093f792aac64ef01d71c3a49d0bb1b9e31b22b0a094622968085b369a8c4480cf5a750b2f93c58d7923d51a977667744e5abeb1ef90d232944b538eb65cea16757d5fc55ec2395c6d4ec5e4ddf5124db5abd62233107b1ebdd817b3f17ea7fa9ada909b1710f5d827135c6db2b31122a87ca33cc97a9550376f5ff99bf1908259f5cd196fc0d99ca87d6088afc615c3fb2616cafcfb960027ed9f3f7778848a76dbc7d7ead668c888366058b275c79fc52b3af810ff8a39b3c78eec3bf5066d36ae09a5d5713695d64257012d9d4937f5b8557ef1f33030716e16e6631b152c2eaef58c94038b8e2c0a8280c3df1b5e9c527d0"));
	EXPECT_EQ(
			exp_mod(fixed_unsigned("2"), fixed_unsigned("ffffffffffffffffffffffffffffffff"), ffdhe2048_p),
			fixed_unsigned("3db7a00d23a760395ec8b5e2c65dd1cee5358b90788d6e2878c8b713ae7cf11d29aa36cb7861fab0ce60310bfe1fea35a6fec93375cf5cc53bea35b0a62ba2f568f59b09cbf56f2d001a1bdb9cc20ea5f5b10ec8ba61ce44fde0f096ad7cd301dd8896e7af7482317d09b36942e7951a4d932701c17a505e1efe0aab311bf2ec11cbe3333d0417066bd3ed94d6bfb1a04da2f8b929d666093c9a623a2b992118bab6163027608488349c8ca457fb3cc2486f46b47e5617ad7a6b5fea7edb779558fbce8674837406c5e9c94e7029ba24394329fabe3887a850f6af57cf99414d3ce5fc80c061bafd046c3c73eddf2f4cfca7412c079a3ae2fd195970f3c4370c")
	);
	EXPECT_EQ(
			exp_mod(
					fixed_unsigned("2"),
					fixed_unsigned("ffffffffffffffffffffffffffffffff31A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE474131A07D962A192A85702CDDB75EBE4741"),
					ffdhe2048_p
			),
			fixed_unsigned("d115085194252476e014d05ba231a9b06013e3731f8802413b190b02f4bd40e020385b3e009f4f41dbedaaec4d7044ad80d92625526d273d4ab1550e1996ec6cc3abc2002b6dca3057f629eadc3ff9691a53a0da04be6e90a59747639bd1cf07e83a084d15324b77996407d7d7f03e79c640096185b9e716ce4d13899cc2e450a626687269419330809c8021cd649086413af5c46692346b470b37843ef484c28855bc85f86c243bb6ff3f5f1c4568053066b96854a5ae3b4447cd021a16e6f2e11041328299d84e7f1256a4d46b1a8e87006be9afd25aa501b55a226c6d14c3556a6c00e18e62443170946774ddb009f764f1fee9db0d179f54f93a1b8b0050")
	);
}

TEST(fixed, unsigned_set) {
	fixed_unsigned first("fedcba9876543210");
	fixed_unsigned<16> second(0xabcd);
	first.set(second);
	EXPECT_EQ(first, fixed_unsigned("fedcba987654abcd"));
	auto n = fixed_unsigned<449>(1) << 448;
	EXPECT_TRUE(n.bit(448));
}

int main() {
	testing::InitGoogleTest();
	return RUN_ALL_TESTS();
}

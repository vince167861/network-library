#include <gtest/gtest.h>
#include "encoding/pem.h"
#include "big_number.h"

TEST(pem, decode_1) {
	constexpr std::string_view data{R"(-----BEGIN CERTIFICATE-----
MIIDfjCCAwSgAwIBAgISA8Jb/y5M/QNlxU0wz9e0wllqMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
MTAeFw0yNDAyMDQwNDU1MThaFw0yNDA1MDQwNDU1MTdaMBMxETAPBgNVBAMTCGll
dGYub3JnMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPG26lAzIFI8A7KJKZnqY
p76Z9GgZuZ0GArk6pKNhhb1oxxuJP7sUzLQXCk601ou1jU8hlRCcD1wP+3BkL1BP
laOCAhcwggITMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUsw04quuarSxxwzb6BFcD
CFvz3agwHwYDVR0jBBgwFoAUWvPtK/w2wjd5uVIw6lRvz1XLLqwwVQYIKwYBBQUH
AQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vZTEuby5sZW5jci5vcmcwIgYIKwYB
BQUHMAKGFmh0dHA6Ly9lMS5pLmxlbmNyLm9yZy8wHwYDVR0RBBgwFoIKKi5pZXRm
Lm9yZ4IIaWV0Zi5vcmcwEwYDVR0gBAwwCjAIBgZngQwBAgEwggEFBgorBgEEAdZ5
AgQCBIH2BIHzAPEAdwCi4r/WHt4vLweg1k5tN6fcZUOwxrUuotq3iviabfUX2AAA
AY1yr3lKAAAEAwBIMEYCIQD1QFiv0YbUky7zgA1ANASQ9WwP09P+3bKiGZoE2D8i
OwIhAKbgBd//DqEdsYFOUPuq7wpX6Kam4k80k5Ha6Ogd9lfTAHYA7s3QZNXbGs7F
XLedtM0TojKHRny87N7DUUhZRnEftZsAAAGNcq95VwAABAMARzBFAiEAnJUuzAY+
RquSu1Zr6WHsSYOwXuM/qNHJloKqgxHbb00CIFtNbB4ONIcArBaW7JdOMkEIUU0b
I4gJ7CrHjy4RuuzYMAoGCCqGSM49BAMDA2gAMGUCMQDTUqkWn+rRU44W3UQVBWtU
XJOCEWpZC5DXVnbaXzK7DeVUNYakIr+nHO601O+R52ECMCQatF0H0Fktj40PArrG
J89GosiD3WFOSdaG7A8+1Qft0eL8CID6dkVUv/2fv6htQw==
-----END CERTIFICATE-----
)"};
	EXPECT_EQ(
		encoding::pem::from(data),
		big_unsigned{"3082037e30820304a003020102021203c25bff2e4cfd0365c54d30cfd7b4c2596a300a06082a8648ce3d0403033032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313024531301e170d3234303230343034353531385a170d3234303530343034353531375a30133111300f06035504031308696574662e6f72673059301306072a8648ce3d020106082a8648ce3d030107034200043c6dba940cc8148f00eca24a667a98a7be99f46819b99d0602b93aa4a36185bd68c71b893fbb14ccb4170a4eb4d68bb58d4f2195109c0f5c0ffb70642f504f95a382021730820213300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e04160414b30d38aaeb9aad2c71c336fa045703085bf3dda8301f0603551d230418301680145af3ed2bfc36c23779b95230ea546fcf55cb2eac305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f65312e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f65312e692e6c656e63722e6f72672f301f0603551d1104183016820a2a2e696574662e6f72678208696574662e6f726730130603551d20040c300a3008060667810c01020130820105060a2b06010401d6790204020481f60481f300f1007700a2e2bfd61ede2f2f07a0d64e6d37a7dc6543b0c6b52ea2dab78af89a6df517d80000018d72af794a0000040300483046022100f54058afd186d4932ef3800d40340490f56c0fd3d3feddb2a2199a04d83f223b022100a6e005dfff0ea11db1814e50fbaaef0a57e8a6a6e24f349391dae8e81df657d3007600eecdd064d5db1acec55cb79db4cd13a23287467cbcecdec351485946711fb59b0000018d72af795700000403004730450221009c952ecc063e46ab92bb566be961ec4983b05ee33fa8d1c99682aa8311db6f4d02205b4d6c1e0e348700ac1696ec974e324108514d1b238809ec2ac78f2e11baecd8300a06082a8648ce3d0403030368003065023100d352a9169fead1538e16dd4415056b545c9382116a590b90d75676da5f32bb0de5543586a422bfa71ceeb4d4ef91e7610230241ab45d07d0592d8f8d0f02bac627cf46a2c883dd614e49d686ec0f3ed507edd1e2fc0880fa764554bffd9fbfa86d43"}.to_bytestring(std::endian::big));
}

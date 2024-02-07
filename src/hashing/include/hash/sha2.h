#pragma once
#include "number/flexible.h"

namespace leaf {

	namespace sha_2 {
		template<std::size_t block_size>
		var_unsigned padding(const var_unsigned& val) {
			auto ext = (val.bits() + 65) % block_size;
			auto ret{val};
			ret.resize(block_size * ((val.bits() + 65) / block_size + 1));
			if (ext)
				ret <<= block_size - ext + 65;
			ret.set(true, block_size - ext + 64);
            ret.set(var_unsigned::from_number(val.bits()), 64);
			return ret;
		}

		template<class T>
		T Ch(T x, T y, T z) {
			return (x & y) ^ (~x & z);
		}

		template<class T>
		T Maj(T x, T y, T z) {
			return (x & y) ^ (x & z) ^ (y & z);
		}
	}

	template<class T>
	T rotate_right(T x, std::size_t D) {
		return (x << (sizeof(T) * 8 - D)) | (x >> D);
	}


	class sha_256 {
		static constexpr uint32_t K[64] {
				0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
				0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
				0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
				0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
				0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
				0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
				0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
				0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

		static uint32_t Sigma_0(uint32_t x) {
			return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
		}

		static uint32_t Sigma_1(uint32_t x) {
			return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
		}

		static uint32_t sigma_0(uint32_t x) {
			return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
		}

		static uint32_t sigma_1(uint32_t x) {
			return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
		}

	public:
        static var_unsigned hash(const var_unsigned& val) {
            std::uint32_t H[8] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
            auto&& D = sha_2::padding<512>(val);
            const auto total_blocks = D.data_units() / 16;
            for (std::size_t i = 0; i < total_blocks; ++i) {
                uint32_t W[64];
                for (std::size_t t = 0; t < 16; ++t)
                    W[t] = D.value<uint32_t>(16 - t - 1 + (total_blocks - i - 1) * 16);
                for (std::size_t t = 16; t < 64; ++t)
                    W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16];
                auto a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                        g = H[6], h = H[7];
                for (std::size_t t = 0; t < 64; ++t) {
                    auto temp_1 = h + Sigma_1(e) + sha_2::Ch(e, f, g) + K[t] + W[t];
                    auto temp_2 = Sigma_0(a) + sha_2::Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + temp_1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp_1 + temp_2;
                }
                H[0] += a, H[1] += b, H[2] += c, H[3] += d, H[4] += e, H[5] += f, H[6] += g, H[7] += h;
            }
            var_unsigned ret{256};
            for (auto i : H) {
                ret <<= sizeof i * 8;
				ret.set(var_unsigned::from_number(i), 32);
            }
            return ret;
        }
	};


	class sha_384 {
		static constexpr uint64_t K[80] {
				0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
				0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
				0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
				0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
				0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
				0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
				0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
				0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
				0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
				0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
				0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
				0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
				0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
				0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
				0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
				0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
				0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
				0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
				0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
				0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
		};

		static uint64_t Sigma_0(uint64_t x) {
			return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
		}

		static uint64_t Sigma_1(uint64_t x) {
			return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
		}

		static uint64_t sigma_0(uint64_t x) {
			return rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7);
		}

		static uint64_t sigma_1(uint64_t x) {
			return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
		}

	public:
        static var_unsigned hash(const var_unsigned& val) {
            uint64_t H[8] {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
            auto&& D = sha_2::padding<1024>(val);
            auto total_blocks = D.data_units() / (128 / var_unsigned::unit_bytes);
            for (std::size_t i = 0; i < total_blocks; ++i) {
                uint64_t W[80];
                for (std::size_t t = 0; t < 16; ++t)
                    W[t] = D.template value<uint64_t>(16 - t - 1 + (total_blocks - i - 1) * 16);
                for (std::size_t t = 16; t < 64; ++t)
                    W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16];
                auto a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                        g = H[6], h = H[7];
                for (std::size_t t = 0; t < 80; ++t) {
                    auto temp_1 = h + Sigma_1(e) + sha_2::Ch(e, f, g) + K[t] + W[t];
                    auto temp_2 = Sigma_0(a) + sha_2::Maj(a, b, c);
                    h = g;
                    g = f;
                    f = e;
                    e = d + temp_1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp_1 + temp_2;
                }
                H[0] += a, H[1] += b, H[2] += c, H[3] += d, H[4] += e, H[5] += f, H[6] += g, H[7] += h;
            }
            var_unsigned ret{384};
            for (uint8_t i = 0; i < 6; ++i) {
                ret <<= 64;
				ret.set(var_unsigned::from_number(H[i]), 64);
            }
            return ret;
        }
	};
}

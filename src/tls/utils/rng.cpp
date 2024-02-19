#include "tls-utils/rng.h"

namespace leaf {

	mt19937_uniform::mt19937_uniform(const std::uint_fast32_t seed)
		: random_engine(seed) {
	}

	byte_string mt19937_uniform::number(std::size_t bytes) {
		byte_string number(bytes, 0);
		for (auto& u: number)
			u = unit();
		return number;
	}

	std::uint8_t mt19937_uniform::unit() {
		return int_distributor(random_engine);
	}
}

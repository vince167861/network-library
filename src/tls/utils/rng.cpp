#include "tls-utils/rng.h"

namespace leaf {

	mt19937_uniform::mt19937_uniform(const std::uint_fast32_t seed)
		: random_engine(seed) {
	}

	var_unsigned mt19937_uniform::number(std::size_t bytes) {
		var_unsigned number{bytes};
		for (auto& u: number.data)
			u = int_distributor(random_engine);
		return number;
	}

	var_unsigned::unit_t mt19937_uniform::unit() {
		return int_distributor(random_engine);
	}
}

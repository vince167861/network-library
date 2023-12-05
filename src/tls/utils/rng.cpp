#include "tls-utils/rng.h"

namespace leaf {

	mt19937_uniform::mt19937_uniform()
			: random_engine(std::random_device{}()) {
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

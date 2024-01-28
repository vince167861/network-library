#pragma once

#include "number/flexible.h"

#include <functional>
#include <random>


namespace leaf {

	class random_number_generator {

	public:
		virtual var_unsigned number(std::size_t bytes) = 0;

		virtual var_unsigned::unit_t unit() = 0;

		virtual ~random_number_generator() = default;
	};


	class mt19937_uniform final: public random_number_generator {
		std::mt19937 random_engine;

		std::uniform_int_distribution<var_unsigned::unit_t> int_distributor;

	public:
		mt19937_uniform(std::uint_fast32_t seed = std::random_device()());

		var_unsigned number(std::size_t bytes) override;

		var_unsigned::unit_t unit() override;
	};
}

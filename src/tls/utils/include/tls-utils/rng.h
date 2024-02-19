#pragma once
#include "common.h"
#include <random>

namespace leaf {

	struct random_number_generator {

		virtual byte_string number(std::size_t bytes) = 0;

		virtual std::uint8_t unit() = 0;

		virtual ~random_number_generator() = default;
	};


	class mt19937_uniform final: public random_number_generator {

		std::mt19937 random_engine;

		std::uniform_int_distribution<std::uint8_t> int_distributor;

	public:
		mt19937_uniform(std::uint_fast32_t seed = std::random_device()());

		byte_string number(std::size_t bytes) override;

		std::uint8_t unit() override;
	};
}

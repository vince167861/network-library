#pragma once
#include "byte_string.h"
#include <cstddef>
#include <random>

struct random_source {

	virtual byte_string operator()(std::size_t length);

	virtual std::byte operator()() = 0;

	virtual ~random_source() = default;
};

struct mt19937_uniform final: random_source {

	mt19937_uniform(const std::uint_fast32_t seed = std::random_device()())
			: engine_(seed) {
	}

	std::byte operator()() override;

private:
	std::mt19937 engine_;

	std::uniform_int_distribution<std::uint8_t> distribution_;
};

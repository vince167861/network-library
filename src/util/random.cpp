#include "random_source.h"

byte_string random_source::operator()(const std::size_t length) {
	byte_string __r;
	__r.reserve(length);
	const auto __c = reinterpret_cast<std::byte*>(__r.data());
	for (std::size_t i = 0; i < length; ++i)
		__c[i] = operator()();
	return __r;
}

std::byte mt19937_uniform::operator()() {
	return static_cast<std::byte>(distribution_(engine_));
}

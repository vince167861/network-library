#pragma once

namespace internal {

	template<class T, template<class...> class B>
	constexpr bool specialization_of = false;

	template<template<class...> class B, class... Args>
	constexpr bool specialization_of<B<Args...>, B> = true;

	template<class T>
	concept is_array = std::is_array_v<std::remove_reference_t<T>>;
}

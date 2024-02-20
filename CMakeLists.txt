cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 23)
set(CXX_STANDARD_REQUIRED ON)
add_compile_options(
		-Werror=return-type -Wno-deprecated-declarations -Wextra -Wpessimizing-move -fconcepts-diagnostics-depth=3
		-Werror=implicit-fallthrough)
enable_testing()

project(leaf)
add_compile_definitions(PLATFORM_${CMAKE_SYSTEM_NAME})

if (${CMAKE_SYSTEM_NAME} STREQUAL Generic)
	add_compile_options(-mlongcalls)
endif ()

include_directories(./src)

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(example)

install(EXPORT leaf DESTINATION .)

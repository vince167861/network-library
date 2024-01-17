cmake_minimum_required(VERSION 3.23)

set(CMAKE_CXX_STANDARD 23)
set(CXX_STANDARD_REQUIRED ON)
add_compile_options(-Werror=return-type -Wno-deprecated-declarations -Wextra -Wpessimizing-move -fconcepts-diagnostics-depth=3)
enable_testing()

project(leaf)
if (${CMAKE_SYSTEM_NAME} STREQUAL Windows)
    add_compile_definitions(PLATFORM=1)
# elseif (${CMAKE_SYSTEM_NAME} STREQUAL Linux)
else ()
    add_compile_definitions(PLATFORM=2)
endif ()

include_directories(./src)

add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(example)

install(EXPORT leaf DESTINATION .)

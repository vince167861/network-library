include_directories(priv-include)

add_library(shared
		util/json.cpp
		util/big_number.cpp
		util/random.cpp)
set_target_properties(shared PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(shared
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(shared PUBLIC FILE_SET shared_headers TYPE HEADERS BASE_DIRS include FILES
		include/byte_string.h
		include/big_number.h
		include/json.h
		include/stl_hash.h
		include/stream_endpoint.h
		include/random_source.h
		include/basic_stream.h
		include/basic_endpoint.h
)
install(TARGETS shared EXPORT leaf
		FILE_SET shared_headers)

link_libraries(shared)

add_subdirectory(crypto)
add_subdirectory(http)
add_subdirectory(tcp)
add_subdirectory(tls)

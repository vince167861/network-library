include_directories(priv-include)

add_library(shared
		util/big_number.cpp
		util/random.cpp)
set_target_properties(shared PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(shared
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(shared PUBLIC FILE_SET shared_headers TYPE HEADERS BASE_DIRS include FILES
		include/internal/lang_util.h
		include/custom_std/format.h
		include/byte_string.h
		include/format/byte_string.h
		include/big_number.h
		include/format/big_number.h
		include/stream_endpoint.h
		include/random_source.h
		include/basic_stream.h
		include/basic_endpoint.h
		include/custom_std/hash.h
		include/format/custom.h
)
install(TARGETS shared EXPORT leaf
		FILE_SET shared_headers)

link_libraries(shared)

add_subdirectory(crypto)
add_subdirectory(http)
add_subdirectory(tcp)
add_subdirectory(tls)

add_library(encoding
		encoding/json.cpp
		encoding/x690.cpp)
target_include_directories(encoding
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(encoding
		PUBLIC FILE_SET enc_headers TYPE HEADERS BASE_DIRS include FILES
		include/encoding/shared_type.h
		include/encoding/pem.h
		include/encoding/base64.h
		include/encoding/json.h
		include/encoding/x690.h)

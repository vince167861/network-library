add_subdirectory(utils)
add_subdirectory(context)
add_subdirectory(record)
add_subdirectory(cipher)
add_subdirectory(key_exchange)
add_subdirectory(extension)
add_subdirectory(handshake)

add_library(tls client.cpp)
target_link_libraries(tls tcp number hashing tls-dh_key tls-extension tls-cipher tls-context)
target_include_directories(tls PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls PUBLIC FILE_SET tls_headers TYPE HEADERS BASE_DIRS include FILES
	include/tls/client.h)
install(TARGETS tls EXPORT leaf
	FILE_SET tls_headers
	LIBRARY)

add_subdirectory(utils)
add_subdirectory(record)
add_subdirectory(cipher)
add_subdirectory(key_exchange)
add_subdirectory(extension)

add_library(tls client.cpp endpoint.cpp)
target_link_libraries(tls tcp number tls-key tls-extension tls-cipher)
target_include_directories(tls PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls PUBLIC FILE_SET tls_headers TYPE HEADERS BASE_DIRS include FILES
	include/tls/client.h
	include/tls/endpoint.h)
install(TARGETS tls EXPORT leaf
	FILE_SET tls_headers
	LIBRARY)

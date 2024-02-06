add_library(tls-context
		endpoint.cpp)
target_link_libraries(tls-context
		tls-key tls-record)
target_include_directories(tls-context
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls-context
		PUBLIC FILE_SET tls_cipher_headers TYPE HEADERS BASE_DIRS include FILES
		include/tls-context/endpoint.h)
install(TARGETS tls-context EXPORT leaf
        FILE_SET tls_cipher_headers
		LIBRARY)

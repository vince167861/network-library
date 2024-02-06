add_library(tls-key
		manager.cpp
		ffdhe2048.cpp
		x25519.cpp)
target_link_libraries(tls-key
		tls-utils tls-cipher)
target_include_directories(tls-key
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls-key
		PUBLIC FILE_SET tls_key_header TYPE HEADERS BASE_DIRS include FILES
		include/tls-key/manager.h
		include/tls-key/ffdhe2048.h
		include/tls-key/x25519.h)
install(TARGETS tls-key EXPORT leaf
        FILE_SET tls_key_header
        LIBRARY)

add_library(tls-cipher
		cipher_suite_aes_gcm.cpp
		cipher_suite.cpp
		cipher_suite_gcm.cpp
		traffic_secret_manager.cpp)
target_link_libraries(tls-cipher
		PUBLIC tls-utils cipher hashing)
target_sources(tls-cipher
		PUBLIC FILE_SET tls_cipher_header TYPE HEADERS BASE_DIRS include FILES
		include/tls-cipher/cipher_suite_gcm.h
		include/tls-cipher/cipher_suite.h
		include/tls-cipher/cipher_suite_aes_gcm.h
		include/tls-cipher/traffic_secret_manager.h
)
target_include_directories(tls-cipher
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(TARGETS tls-cipher EXPORT leaf
        FILE_SET tls_cipher_header)

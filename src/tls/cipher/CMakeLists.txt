add_library(tls-cipher
		aes_gcm.cpp
		cipher_suite.cpp
		gcm_cipher.cpp)
target_link_libraries(tls-cipher
		PUBLIC tls-utils tls-record cipher hashing)
target_sources(tls-cipher
		PUBLIC FILE_SET tls_cipher_header TYPE HEADERS BASE_DIRS include FILES
		include/tls-cipher/gcm_cipher.h
		include/tls-cipher/cipher_suite.h
		include/tls-cipher/aes_gcm.h
)
target_include_directories(tls-cipher
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(TARGETS tls-cipher EXPORT leaf
        FILE_SET tls_cipher_header)

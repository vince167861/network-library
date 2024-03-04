add_library(tls-utils
		utils/type.cpp)
target_sources(tls-utils
		PUBLIC FILE_SET tls_utils_h TYPE HEADERS BASE_DIRS include FILES
		include/tls/util/type.h)
target_include_directories(tls-utils
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

add_subdirectory(record)

add_library(tls-cipher
		cipher/cipher_suite.cpp
		cipher/cipher_suite_gcm.cpp
		cipher/cipher_suite_aes_gcm.cpp
		cipher/traffic_secret_manager.cpp)
target_link_libraries(tls-cipher
		PUBLIC tls-utils crypto)
target_sources(tls-cipher
		PUBLIC FILE_SET tls_cipher_h TYPE HEADERS BASE_DIRS include FILES
		include/tls/cipher/cipher_suite.h
		include/tls/cipher/cipher_suite_gcm.h
		include/tls/cipher/cipher_suite_aes_gcm.h
		include/tls/cipher/traffic_secret_manager.h)
target_include_directories(tls-cipher
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

add_library(tls-key
		key/manager.cpp key/ffdhe2048.cpp key/x25519.cpp)
target_sources(tls-key
		PUBLIC FILE_SET tls_key_h TYPE HEADERS BASE_DIRS include FILES
		include/tls/key/manager.h
		include/tls/key/ffdhe2048.h
		include/tls/key/x25519.h)
target_link_libraries(tls-key
		crypto tls-utils)
target_include_directories(tls-key
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

add_subdirectory(extension)

add_library(tls
		client.cpp endpoint.cpp)
target_sources(tls
		PUBLIC FILE_SET tls_h TYPE HEADERS BASE_DIRS include FILES
		include/tls/client.h
		include/tls/endpoint.h)
target_link_libraries(tls
		tls-key tls-extension tls-cipher)
target_include_directories(tls
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)

install(TARGETS tls tls-utils tls-key tls-cipher EXPORT leaf
		FILE_SET tls_h
		FILE_SET tls_utils_h
		FILE_SET tls_key_h
		FILE_SET tls_cipher_h
		LIBRARY)

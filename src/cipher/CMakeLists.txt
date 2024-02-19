add_library(cipher
		aes.cpp
		gcm.cpp
		hmac.cpp
		ecc.cpp)
target_link_libraries(cipher
		PUBLIC number)
target_include_directories(cipher
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(cipher
		PUBLIC FILE_SET cipher_headers TYPE HEADERS BASE_DIRS include FILES
		include/cipher/aes.h
		include/cipher/gcm.h
		include/cipher/ecc.h
		include/cipher/sha2.h
		include/cipher/hmac.h
)
install(TARGETS cipher EXPORT leaf
		FILE_SET cipher_headers
		LIBRARY)

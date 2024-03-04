add_library(crypto
		aes.cpp gcm.cpp hmac.cpp ecc.cpp sha2.cpp)
target_include_directories(crypto
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(crypto
		PUBLIC FILE_SET crypto_h TYPE HEADERS BASE_DIRS include FILES
		include/crypto/aes.h
		include/crypto/gcm.h
		include/crypto/ecc.h
		include/crypto/sha2.h
		include/crypto/hmac.h
)
install(TARGETS crypto EXPORT leaf
		FILE_SET crypto_h
		LIBRARY)

add_library(cipher INTERFACE)
target_link_libraries(cipher
		INTERFACE number)
target_include_directories(cipher
		INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(cipher
		PUBLIC FILE_SET cipher_headers TYPE HEADERS BASE_DIRS include FILES
		include/cipher/aes.h
		include/cipher/gcm.h
)
install(TARGETS cipher EXPORT leaf
		FILE_SET cipher_headers)

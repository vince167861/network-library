add_library(hashing
		hmac.cpp)
target_link_libraries(hashing
		number)
target_include_directories(hashing
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(hashing
		PUBLIC FILE_SET hashing_headers TYPE HEADERS BASE_DIRS include FILES
		include/hash/hmac.h
		include/hash/sha2.h
)
install(TARGETS hashing EXPORT leaf
		FILE_SET hashing_headers)

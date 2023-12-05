add_library(tls-utils
		rng.cpp
		data_type.cpp
)
target_sources(tls-utils
		PUBLIC FILE_SET tls_utils_headers TYPE HEADERS BASE_DIRS include FILES
		include/tls-utils/rng.h
		include/tls-utils/type.h
)
target_link_libraries(tls-utils
		number)
target_include_directories(tls-utils
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
install(TARGETS tls-utils EXPORT leaf
		FILE_SET tls_utils_headers)

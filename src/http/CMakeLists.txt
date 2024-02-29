add_library(http_common
		common/uri.cpp
		common/message.cpp
)
target_include_directories(http_common
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(http_common
		PUBLIC FILE_SET http_common_headers TYPE HEADERS BASE_DIRS include FILES
		include/http/uri.h
		include/http/message.h
)
install(TARGETS http_common EXPORT leaf
	FILE_SET http_common_headers)

add_library(http1_1
		http1_1/client.cpp
)
target_include_directories(http1_1
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
target_sources(http1_1
		PUBLIC FILE_SET http_headers TYPE HEADERS BASE_DIRS include FILES
		include/http1_1/client.h
)
target_link_libraries(http1_1
		http_common)
install(TARGETS http1_1 EXPORT leaf
		FILE_SET http_headers)

add_library(http2
		http2/client.cpp
		http2/frame.cpp
		http2/header_packer.cpp
		http2/connection_state.cpp
		http2/type.cpp
		http2/stream_state.cpp
		http2/huffman.cpp
)
target_link_libraries(http2
		http_common)
target_include_directories(http2
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
target_sources(http2
		PUBLIC FILE_SET http2_headers TYPE HEADERS BASE_DIRS include FILES
		include/http2/client.h
		include/http2/frame.h
		include/http2/header_packer.h
		include/http2/state.h
		include/http2/type.h
)

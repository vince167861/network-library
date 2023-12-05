add_library(http
		http_client.cpp
		http_request.cpp
		http_response.cpp
		url.cpp
)
target_include_directories(http
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
target_sources(http
		PUBLIC FILE_SET http_headers TYPE HEADERS BASE_DIRS include FILES
		include/http/client.h
		include/http/http_exception.h
		include/http/message.h
		include/http/request.h
		include/http/response.h
		include/http/url.h
)
install(TARGETS http EXPORT leaf
		FILE_SET http_headers)

add_library(http2
		http2_client.cpp
		http2_frame.cpp
		http2_header_packer.cpp
		http2_context.cpp
		http2_request.cpp
		http2_response.cpp
		http2_type.cpp
)
target_link_libraries(http2
		http tls)
target_include_directories(http2
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
target_sources(http2
		PUBLIC FILE_SET http2_headers TYPE HEADERS BASE_DIRS include FILES
		include/http2/client.h
		include/http2/frame.h
		include/http2/header_packer.h
		include/http2/context.h
		include/http2/message.h
		include/http2/request.h
		include/http2/response.h
		include/http2/type.h
)

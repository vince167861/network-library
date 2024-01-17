add_library(http_message
	url.cpp
	http_message.cpp
	http_request.cpp
	http_response.cpp
		http_event_stream.cpp
)
target_include_directories(http_message
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/http> $<INSTALL_INTERFACE:include/http>)
target_sources(http_message
	PUBLIC FILE_SET http_message_headers TYPE HEADERS BASE_DIRS include FILES
	include/http/url.h
	include/http/message.h
	include/http/request.h
	include/http/response.h
	include/http/event_stream.h
)
install(TARGETS http_message EXPORT leaf
	FILE_SET http_message_headers)

add_library(http
		http_client.cpp
)
target_include_directories(http
	PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/http> $<INSTALL_INTERFACE:include/http>
)
target_sources(http
		PUBLIC FILE_SET http_headers TYPE HEADERS BASE_DIRS include FILES
		include/http/client.h
		include/http/http_exception.h
)
target_link_libraries(http
	http_message)
install(TARGETS http EXPORT leaf
		FILE_SET http_headers)

add_library(http2
		http2_client.cpp
		http2_frame.cpp
		http2_header_packer.cpp
		http2_context.cpp
		http2_type.cpp
		http2_stream.cpp
)
target_link_libraries(http2
		http_message tls)
target_include_directories(http2
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
target_sources(http2
		PUBLIC FILE_SET http2_headers TYPE HEADERS BASE_DIRS include FILES
		include/http2/client.h
		include/http2/frame.h
		include/http2/header_packer.h
		include/http2/context.h
		include/http2/type.h
		include/http2/stream.h
)

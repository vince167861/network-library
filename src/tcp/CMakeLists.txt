add_library(tcp)
set_target_properties(tcp PROPERTIES LINKER_LANGUAGE CXX)
if (${CMAKE_SYSTEM_NAME} STREQUAL Windows)
	target_link_libraries(tcp PUBLIC Ws2_32.lib)
endif ()
target_sources(tcp PUBLIC FILE_SET tcp_headers TYPE HEADERS BASE_DIRS include FILES
	include/tcp/endpoint.h
	include/tcp/client.h
	include/tcp/server.h
)
target_include_directories(tcp
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
)
install(TARGETS tcp EXPORT leaf
		FILE_SET tcp_headers
		LIBRARY)

include_directories(priv-include)

add_library(shared INTERFACE)
target_include_directories(shared
		INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(shared INTERFACE FILE_SET shared_headers TYPE HEADERS BASE_DIRS include FILES
		include/basic_client.h
		include/basic_stream.h
		include/task.h
)
install(TARGETS shared EXPORT leaf
		FILE_SET shared_headers)

link_libraries(shared)

add_subdirectory(json)
add_subdirectory(number)
add_subdirectory(cipher)
add_subdirectory(hashing)
add_subdirectory(http)
add_subdirectory(tcp)
add_subdirectory(tls)

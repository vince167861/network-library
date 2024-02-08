include_directories(priv-include)

add_library(shared)
set_target_properties(shared PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories(shared
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(shared PUBLIC FILE_SET shared_headers TYPE HEADERS BASE_DIRS include FILES
		include/task.h
		include/binary_object.h
		include/byte_stream.h
		include/basic_endpoint.h
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

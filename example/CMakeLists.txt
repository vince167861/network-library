if (${CMAKE_SYSTEM_NAME} STREQUAL Windows)

	add_executable(example-http_client
			http_client.cpp)
	target_link_libraries(example-http_client
			tcp http)

	add_executable(example-http2_client
			http2_client.cpp)
	target_link_libraries(example-http2_client
			tcp http2)

	add_executable(example-http2s_client
			http2s_client.cpp)
	target_link_libraries(example-http2s_client
			tcp tls http2)

endif ()

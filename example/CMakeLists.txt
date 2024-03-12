if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL Generic)

	add_executable(example-http_client
			http/client.cpp)
	target_link_libraries(example-http_client
			tcp http1_1)

	add_executable(example-http_server
			http/server.cpp)
	target_link_libraries(example-http_server
			tcp http1_1)

	add_executable(example-https_client
			https_client.cpp)
	target_link_libraries(example-https_client
			tcp tls http1_1)

	add_executable(example-http2_client
			http2_client.cpp)
	target_link_libraries(example-http2_client
			tcp http2)

	add_executable(example-http2s_client
			http2s_client.cpp)
	target_link_libraries(example-http2s_client
			tcp tls http2)

	add_executable(example-https_event_stream_client
			https_event_stream_client.cpp)
	target_link_libraries(example-https_event_stream_client
			tcp tls http1_1)
endif ()

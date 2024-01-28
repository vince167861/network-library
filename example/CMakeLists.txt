if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL Generic)

	add_executable(example-http_client
			http_client.cpp)
	target_link_libraries(example-http_client
			tcp http)

	add_executable(example-https_client
			https_client.cpp)
	target_link_libraries(example-https_client
			tcp tls http)

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
			tcp tls http)

	add_executable(example-http2s_event_stream_client
			http2s_event_stream_client.cpp)
	target_link_libraries(example-http2s_event_stream_client
			tcp tls http2)

endif ()

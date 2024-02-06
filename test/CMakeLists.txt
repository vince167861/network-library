if (${CMAKE_SYSTEM_NAME} STREQUAL Windows)
	find_package(GTest CONFIG REQUIRED)
	include(GoogleTest)

	link_libraries(GTest::gtest)

	add_executable(test-number number.cpp)
	target_link_libraries(test-number number)

	add_executable(test-hashing hashing.cpp)
	target_link_libraries(test-hashing hashing)
	gtest_discover_tests(test-hashing)

	add_executable(test-json json.cpp)
	target_link_libraries(test-json json)
	gtest_discover_tests(test-json)

	add_executable(test-tls_client tls_client.cpp)
	target_link_libraries(test-tls_client tls)
	gtest_discover_tests(test-tls_client)

	add_executable(test-http_url http_url.cpp)
	target_link_libraries(test-http_url http)
	gtest_discover_tests(test-http_url)

	add_executable(test-http2 http2.cpp)
	target_link_libraries(test-http2 http2)
	gtest_discover_tests(test-http2)

	add_executable(test-tcp tcp.cpp)
	target_link_libraries(test-tcp tcp)
	gtest_discover_tests(test-tcp)

	add_executable(test-tls tls/key_exchange.cpp)
	target_link_libraries(test-tls tls)

	add_executable(test-cipher cipher.cpp)
	target_link_libraries(test-cipher cipher)
endif ()

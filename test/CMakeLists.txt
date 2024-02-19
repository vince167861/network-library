 find_package(GTest CONFIG)

if (GTest_FOUND)

	include(GoogleTest)
	link_libraries(GTest::gtest GTest::gmock)

	add_executable(test-number
			number/big_number.cpp)
	target_link_libraries(test-number number)

	add_executable(test-json json.cpp)
	target_link_libraries(test-json json)

	add_executable(test-http
			http/header_packer.cpp
			http/url.cpp)
	target_link_libraries(test-http http http2)

	add_executable(test-tcp tcp.cpp)
	target_link_libraries(test-tcp tcp)

	add_executable(test-tls
			tls/key_exchange.cpp
			tls/cipher.cpp
			tls/record.cpp)
	target_link_libraries(test-tls tls)

	add_executable(test-cipher
			cipher/cipher.cpp
			cipher/aes.cpp
			cipher/gcm.cpp
			cipher/hash.cpp)
	target_link_libraries(test-cipher cipher)
endif ()

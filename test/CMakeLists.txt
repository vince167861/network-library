find_package(GTest CONFIG REQUIRED)
include(GoogleTest)

link_libraries(GTest::gtest)

add_executable(test-number number.cpp)
target_link_libraries(test-number number)
gtest_discover_tests(test-number)

add_executable(test-hashing hashing.cpp)
target_link_libraries(test-hashing hashing)
gtest_discover_tests(test-hashing)

add_executable(test-aes aes.cpp)
target_link_libraries(test-aes cipher)
gtest_discover_tests(test-aes)

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

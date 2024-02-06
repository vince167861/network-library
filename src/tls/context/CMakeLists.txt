add_library(tls-context endpoint.cpp)
target_link_libraries(tls-context tls-dh_key tls-cipher)
target_include_directories(tls-context PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
set_property(TARGET tls-context PROPERTY PUBLIC_HEADER include/tls-context/endpoint.h)
install(TARGETS tls-context EXPORT leaf
        PUBLIC_HEADER DESTINATION include/tls-context)

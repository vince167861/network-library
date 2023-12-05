add_library(tls-record alert.cpp record.cpp)
target_link_libraries(tls-record PUBLIC tls-utils tls-handshake tls-context)
target_include_directories(tls-record PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
set_property(TARGET tls-record PROPERTY PUBLIC_HEADER include/tls-record/record.h include/tls-record/alert.h)
install(TARGETS tls-record EXPORT leaf
        PUBLIC_HEADER DESTINATION include/tls-record)

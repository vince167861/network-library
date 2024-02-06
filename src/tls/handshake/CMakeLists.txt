add_library(tls-handshake
        certificate.cpp certificate_verify.cpp client_hello.cpp encrypted_extension.cpp finished.cpp key_update.cpp
        new_session_ticket.cpp server_hello.cpp handshake.cpp)
target_include_directories(tls-handshake
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_link_libraries(tls-handshake
		PUBLIC tcp tls-extension tls-record tls-cipher tls-context)
set_property(TARGET tls-handshake PROPERTY PUBLIC_HEADER include/tls-handshake/handshake.h)
install(TARGETS tls-handshake EXPORT leaf
        PUBLIC_HEADER DESTINATION include/tls-handshake)

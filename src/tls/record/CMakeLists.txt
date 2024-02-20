add_library(tls-record
		alert.cpp
		record.cpp
		certificate.cpp
		certificate_verify.cpp
		client_hello.cpp
		encrypted_extension.cpp
		finished.cpp
		key_update.cpp
		new_session_ticket.cpp
		server_hello.cpp
		handshake.cpp
		certificate_request.cpp)
target_link_libraries(tls-record
		PUBLIC tls-utils tls-extension)
target_include_directories(tls-record
		PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls-record PUBLIC FILE_SET tls_record_headers TYPE HEADERS BASE_DIRS include FILES
		include/tls-record/record.h
		include/tls-record/alert.h
		include/tls-record/handshake.h)
install(TARGETS tls-record EXPORT leaf
		FILE_SET tls_record_headers
		LIBRARY)

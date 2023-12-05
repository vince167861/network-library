add_library(tls-extension extension.cpp key_share.cpp
		supported_versions.cpp
		supported_groups.cpp
		signature_algorithms.cpp
		server_name.cpp
		renegotiation_info.cpp
		session_ticket.cpp
		psk_key_exchange_modes.cpp
		record_size_limit.cpp
		alpn.cpp)
target_link_libraries(tls-extension tcp tls-utils tls-record)
target_include_directories(tls-extension PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
set_property(TARGET tls-extension PROPERTY PUBLIC_HEADER include/tls-extension/extension.h)
install(TARGETS tls-extension EXPORT leaf
        PUBLIC_HEADER DESTINATION include/tls-extension
        LIBRARY)

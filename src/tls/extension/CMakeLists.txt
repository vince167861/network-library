add_library(tls-extension
		extension.cpp
		key_share.cpp
		supported_versions.cpp
		supported_groups.cpp
		signature_algorithms.cpp
		server_name.cpp
		renegotiation_info.cpp
		session_ticket.cpp
		psk_key_exchange_modes.cpp
		record_size_limit.cpp
		alpn.cpp)
target_link_libraries(tls-extension tcp tls-utils tls-record tls-key)
target_include_directories(tls-extension PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_sources(tls-extension PUBLIC FILE_SET tls_ext_h TYPE HEADERS BASE_DIRS include FILES
		include/tls-extension/extension.h
)
install(TARGETS tls-extension EXPORT leaf
		FILE_SET tls_ext_h
		LIBRARY)

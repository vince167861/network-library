add_library(tls-dh_key manager.cpp ffdhe2048.cpp x25519.cpp)
target_link_libraries(tls-dh_key tls-utils)
target_include_directories(tls-dh_key PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
set_property(TARGET tls-dh_key PROPERTY PUBLIC_HEADER
        include/tls-key/manager.h include/tls-key/ffdhe2048.h include/tls-key/x25519.h include/tls-key/ecc.h)
install(TARGETS tls-dh_key EXPORT leaf
        PUBLIC_HEADER DESTINATION include/tls-key
        LIBRARY)

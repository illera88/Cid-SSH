cmake_minimum_required(VERSION 3.13)

set(OPENSSL_USE_STATIC_LIBS TRUE)
set(OPENSSL_MSVC_STATIC_RT TRUE)
include(FindOpenSSL)

set(WS_PROXY_SERVER_SOURCE_FILES 
		ws_proxy_server.cpp
	)

set(WS_PROXY_SERVER_HEADER_FILES 
	ws_proxy_server.h
    tcp_proxy.h
)

add_executable(ws_proxy_server ${WS_PROXY_SERVER_SOURCE_FILES} ${WS_PROXY_SERVER_HEADER_FILES})

add_dependencies(ws_proxy_server libssh_builder)
target_include_directories(ws_proxy_server PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/..)
target_include_directories(ws_proxy_server PRIVATE ${LIBSSH_INCLUDE_DIR})
target_include_directories(ws_proxy_server PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ws_proxy_server libssh)
target_link_libraries(ws_proxy_server OpenSSL::SSL)
target_link_libraries(ws_proxy_server OpenSSL::Crypto)

target_include_directories(ws_proxy_server PRIVATE "../externals/asio/asio/include/")
target_include_directories(ws_proxy_server PRIVATE "../externals/websocketpp/")

set_property(TARGET ws_proxy_server PROPERTY CXX_STANDARD 11)
set_property(TARGET ws_proxy_server PROPERTY CXX_STANDARD_REQUIRED ON)


if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
target_link_libraries(ws_proxy_server ${LIBSSL_LIBRARY})
target_link_libraries(ws_proxy_server ${LIBCRYPTO_LIBRARY})
target_link_libraries(ws_proxy_server Ws2_32.lib Crypt32.lib)

target_include_directories(ws_proxy_server PRIVATE "${LIBSSL_INCLUDE_DIR}")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /MP")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT /MP -DIS_DEBUG")

elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
endif()

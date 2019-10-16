add_executable(ws_proxy_server ws_proxy_server.cpp)
add_dependencies(ws_proxy_server libssh_builder)

target_include_directories(ws_proxy_server
    PRIVATE
        ${LIBSSH_INCLUDE_DIR}
)

target_compile_features(ws_proxy_server PRIVATE cxx_std_17)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(ws_proxy_server Ws2_32.lib)
    set_target_properties(ws_proxy_server PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (ws_proxy_server PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

target_link_libraries(ws_proxy_server
    libssh  # Link against libssh
    WebsocketsWrapper  # Link against our WebsocketsWrapper
)

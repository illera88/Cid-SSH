add_executable(wsproxy server.cpp)
add_dependencies(wsproxy libssh_builder)

# Add Multi-processor compilation
if(MSVC)
  add_definitions(/MP)
endif()

target_include_directories(wsproxy
    PRIVATE
        ${LIBSSH_INCLUDE_DIR}
)

target_compile_features(wsproxy PRIVATE cxx_std_17)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(wsproxy Ws2_32.lib)
    set_target_properties(wsproxy PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (wsproxy PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS)
endif()

target_link_libraries(wsproxy
    libssh  # Link against libssh
    WebsocketsWrapper  # Link against our WebsocketsWrapper
)

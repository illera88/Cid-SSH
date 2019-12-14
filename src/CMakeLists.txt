# Find out if we have threading available
set(CMAKE_THREAD_PREFER_PTHREADS ON)
find_package(Threads)

if (Threads_FOUND AND CMAKE_USE_PTHREADS_INIT)
 set(HAVE_PTHREAD 1)
endif ()

configure_file(config.h.cmake config.h)

if (${WITH_WEBSOCKETS})
    add_subdirectory(websockets)
endif()

add_subdirectory(malware)

if(${WITH_WSPROXY})
	add_subdirectory(wsproxyserver)
endif()

if(${BUILD_CONTROLER})
    # Even if enabled, we don't build this on Windows
    if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
		add_subdirectory(controller)
	endif()	
endif()

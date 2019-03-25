cmake_minimum_required(VERSION 2.8)
project(CidSSH)

set(CidSSH_SOURCE_FILES 
    src/CidSSH.cpp
    src/server.cpp
    src/sts_queue.c
    src/socks_proxy.c
    src/client.cpp
)

SET(CidSSH_HEADER_FILES
    src/server.h
    src/sts_queue.h
    src/socks_proxy.h
    src/global.h
    src/client.h
)

add_executable(CidSSH ${CidSSH_SOURCE_FILES} ${CidSSH_HEADER_FILES})

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    #ToDo
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    # Option to set the path to the statically compiled libssh
    set(LIBSSH_STATIC_PATH "" CACHE FILEPATH "Path to the build folder for libssh with the config.h file and the include folder")
    if(NOT (LIBSSH_STATIC_PATH))
        message(FATAL_ERROR "Path required for LIBSSH_STATIC_PATH")
    endif()

    # Option to set the path to the statically compiled openssl lib
    set(OPENSSL_STATIC_PATH "" CACHE FILEPATH "Path to the static openssl static library")
    if(NOT (OPENSSL_STATIC_PATH))
        message(FATAL_ERROR "Path required for OPENSSL_STATIC_PATH")
    endif()

    target_compile_definitions(CidSSH PRIVATE "-DHAVE_PTHREAD")    
    target_link_libraries(CidSSH "${LIBSSH_STATIC_PATH}/libssh.a")
    target_link_libraries(CidSSH "${OPENSSL_STATIC_PATH}/libcrypto.a")
    target_link_libraries(CidSSH "-lutil")

    target_include_directories(CidSSH PRIVATE "${LIBSSH_STATIC_PATH}/include/")
    target_include_directories(CidSSH PRIVATE "${OPENSSL_STATIC_PATH}/include/")

    if(${CMAKE_BUILD_TYPE} MATCHES "Debug") # Non static version, to compile in ubuntu without problems
        target_link_libraries(CidSSH "-lpthread")
        target_link_libraries(CidSSH "-ldl")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fsanitize=address -lasan")
    else() #Static version
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
    endif()
    #g++ -static CidSSH.cpp server.cpp /usr/local/lib/libssh.a /usr/local/lib/libcrypto.a /usr/lib/x86_64-linux-gnu/libutil.a -ldl -pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive
    #target_link_libraries(CidSSH "-lssh")
    #target_link_libraries(CidSSH "-lcrypto")
    #target_link_libraries(CidSSH "-Wl,-Bstatic /usr/lib/x86_64-linux-gnu/libutil.a -Wl,-Bdynamic")
    # Not sure why cmake tries to use -lutil if I don't specific the -Wl,-Bstatic
    #target_link_libraries(CidSSH "-Wl,-Bstatic /usr/lib/x86_64-linux-gnu/libutil.a")
    # This is the way to link pthread statically
    #target_link_libraries(CidSSH "-Wl,-Bdynamic -lpthread -ldl -Wl,-Bstatic")
    #target_link_libraries(CidSSH "-pthread -Wl,--whole-archive -lpthread -Wl,--no-whole-archive")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    # Option to set the path to the statically compiled libssh
    set(LIBSSH_STATIC_PATH "" CACHE FILEPATH "Path to the build folder for libssh with the config.h file and the include folder")
    if(NOT (LIBSSH_STATIC_PATH))
        message(FATAL_ERROR "Path required for LIBSSH_STATIC_PATH")
    endif()

    target_include_directories(CidSSH PRIVATE "${LIBSSH_STATIC_PATH}/")
    target_include_directories(CidSSH PRIVATE "${LIBSSH_STATIC_PATH}/include/")
    #/usr/local/opt/gcc/bin/g++-8 -std=gnu++11 -static-libgcc -static-libstdc++ CidSSH.cpp server.cpp -I/usr/local/opt/openssl/include/ /usr/local/lib/libssh.a /usr/local/opt/openssl/lib/libcrypto.a -lutil -lpthread
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -static-libgcc -static-libstdc++")
    # We want to use the gcc installed with brew instead of the system one
    set(CMAKE_C_COMPILER "/usr/local/opt/gcc/bin/gcc-8")
    set(CMAKE_CXX_COMPILER "/usr/local/opt/gcc/bin/g++-8")
    target_include_directories(CidSSH PRIVATE "/usr/local/opt/openssl/include/")
    target_link_libraries(CidSSH "${LIBSSH_STATIC_PATH}/libssh.a")
    target_link_libraries(CidSSH "/usr/local/opt/openssl/lib/libcrypto.a")
    target_link_libraries(CidSSH "-lutil")
    target_link_libraries(CidSSH "-lpthread")
    target_compile_definitions(CidSSH PRIVATE "-DHAVE_PTHREAD")
endif()

if(${CMAKE_BUILD_TYPE} MATCHES "Debug")
    target_compile_definitions(CidSSH PRIVATE "-DIS_DEBUG")
else() # Release by default
    # Strip the binary
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")
endif()
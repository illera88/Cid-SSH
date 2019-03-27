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
    set(LIBSSL_INCLUDE_DIR "" CACHE PATH "Path to OpenSSL include dir")
    set(LIBSSL_LIBRARY "" CACHE FILEPATH "Path to LIBSSL_LIBRARY library")
    set(LIBCRYPTO_LIBRARY "" CACHE FILEPATH "Path to LIBCRYPTO_LIBRARY library")
    
    set(LIBSSH_LIBRARY "" CACHE FILEPATH "Path to libssh library")
    set(LIBSSH_INCLUDE_DIR "" CACHE PATH "Path to libssh include dir. Will contain config.h")

    if(NOT (LIBSSH_LIBRARY))
        message(FATAL_ERROR "Path required for LIBSSH_STATIC_PATH")
    endif()

    if(NOT (LIBSSL_INCLUDE_DIR))
        message(FATAL_ERROR "Path required for LIBSSL_INCLUDE_DIR")
    endif()

    if(NOT (LIBSSL_LIBRARY))
        message(FATAL_ERROR "Path required for LIBSSL_LIBRARY")
    endif()

    if(NOT (LIBCRYPTO_LIBRARY))
        message(FATAL_ERROR "Path required for LIBCRYPTO_LIBRARY")
    endif()

    target_link_libraries(CidSSH ${LIBSSL_LIBRARY})
    target_link_libraries(CidSSH ${LIBCRYPTO_LIBRARY})
    target_link_libraries(CidSSH ${LIBSSH_LIBRARY})

    target_link_libraries(CidSSH Ws2_32.lib Crypt32.lib)

    target_include_directories(CidSSH PRIVATE "${LIBSSH_INCLUDE_DIR}")
    target_include_directories(CidSSH PRIVATE "${LIBSSL_INCLUDE_DIR}")

    target_compile_definitions (CidSSH PUBLIC _CRT_SECURE_NO_WARNINGS LIBSSH_STATIC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /MP")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MT /MP -DIS_DEBUG")

elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LIBSSH_LIBRARY "" CACHE FILEPATH "Path to the static libssh.a")
    if(NOT (LIBSSH_LIBRARY))
        message(FATAL_ERROR "Path required for LIBSSH_LIBRARY")
    endif()

    set(LIBSSH_INCLUDE "" CACHE FILEPATH "Path to the build folder for libssh with the config.h file and the include folder")
    if(NOT (LIBSSH_INCLUDE))
        message(FATAL_ERROR "Path required for LIBSSH_INCLUDE")
    endif()

    set(LIBSSH_CONFIG_FOLDER "" CACHE FILEPATH "Path to the folder with the file config.h for libssh")
    if(NOT (LIBSSH_CONFIG_FOLDER))
        message(FATAL_ERROR "Path required for LIBSSH_CONFIG_FOLDER")
    endif()

    target_compile_definitions(CidSSH PRIVATE "-DHAVE_PTHREAD")    
    target_link_libraries(CidSSH "${LIBSSH_LIBRARY}")
    target_link_libraries(CidSSH "-lutil")
    target_link_libraries(CidSSH "-lcrypto")

    target_include_directories(CidSSH PRIVATE "${LIBSSH_CONFIG_FOLDER}")
    target_include_directories(CidSSH PRIVATE "${LIBSSH_INCLUDE}")

    if(${CMAKE_BUILD_TYPE} MATCHES "Debug") # Non static version, to compile in ubuntu without problems
        target_link_libraries(CidSSH "-lpthread")
        target_link_libraries(CidSSH "-ldl")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -fsanitize=address -lasan")
        target_compile_definitions(CidSSH PRIVATE "-DIS_DEBUG")
    else() #Static version
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++ -s")
    endif()
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
    target_link_libraries(CidSSH "${LIBSSH_STATIC_PATH}/libssh.a")
    target_link_libraries(CidSSH "/usr/local/opt/openssl/lib/libcrypto.a")
    target_link_libraries(CidSSH "-lutil")
    target_link_libraries(CidSSH "-lpthread")
    target_compile_definitions(CidSSH PRIVATE "-DHAVE_PTHREAD")
endif()

